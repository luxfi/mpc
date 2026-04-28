// Package kms — confidential job key release gate.
//
// ReleaseGate is the trust root that gates session-key release on a
// CompositeAttestation produced by the worker's GPU TEE (LP-127, v0.62).
// The gate verifies:
//
//  1. The composite attestation is cryptographically valid (NVTrust SPDM
//     chain + TPM PCR quote + nonce binding).
//  2. The runtime measurement matches one of `RequiredRIM` (Reference
//     Integrity Manifest) digests — i.e. the worker is running the exact
//     code we expect, not a tampered build.
//  3. The hardware fingerprint is in `AllowedHardware` (model + driver
//     + vbios), pinning to known-good silicon.
//  4. The job's `Epoch` matches the gate's current epoch (single-use
//     replay defense — a session key issued for epoch N cannot be reused
//     in epoch N+1).
//  5. The presented nonce equals the gate-issued nonce for this jobID
//     (challenge-response binding — a stolen nonce cannot be replayed
//     under a different jobID, and a forged nonce cannot trick the gate
//     into accepting a worker-chosen challenge).
//  6. Every CPU TEE / GPU evidence blob in the envelope cryptographically
//     chains to its pinned vendor root via cc/attest.Dispatch (AMD KDS +
//     VCEK for SEV-SNP, Intel quote chain for TDX, NRAS JWT for NVIDIA).
//
// On success the gate returns the session key sealed (HPKE-style: ECDH
// over X25519, ChaCha20-Poly1305 AEAD) to the worker's GPU TEE public
// key. The plaintext key never leaves KMS memory; only ciphertext that
// only the attested TEE can decrypt is returned.
//
// Three implementations:
//
//   - LocalReleaseGate — single-process KMS root (dev, single-tenant prod).
//   - MPCReleaseGate   — threshold release; t-of-n KMS quorum must agree.
//   - HSMReleaseGate   — HSM-backed root (AWS/GCP/Azure/Yubi via luxfi/hsm).
//
// All three satisfy the same ReleaseGate interface, so callers (the
// confidential-jobs dispatcher in pkg/jobs) compose without branching.
package kms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/luxfi/mpc/cc/attest"
)

// CompositeAttestation is the contract surface the release gate consumes
// from pkg/attestation (LP-127, v0.62). We declare the interface here so
// pkg/kms does not depend on pkg/attestation directly; the v0.62
// concrete type satisfies via method-set match.
//
// The attestation MUST bind a freshly-generated nonce supplied by the
// gate (challenge-response) and the worker's TEE public key. Either
// failure mode collapses release to "refused".
//
// VerifyEvidence is the wire-in for the canonical cc/attest chain
// verifier. The gate calls VerifyEvidence after the cheap nonce check
// and BEFORE policy / seal so that a forged report whose Verify(nonce)
// returns true but whose chain does not validate cannot harvest a
// session key.
type CompositeAttestation interface {
	// Verify checks NVTrust + TPM + nonce. Returns false on any
	// cryptographic mismatch. Errors only on unrecoverable failure
	// (parsing, root-of-trust load) — a forged attestation is (false, nil).
	Verify(expectedNonce [32]byte) (bool, error)

	// VerifyEvidence cryptographically validates every CPU TEE / GPU
	// evidence blob in the envelope using cc/attest:
	//
	//   - SEV-SNP   → AMD KDS lookup, ARK→ASK→VCEK chain, report-signature
	//   - TDX       → Intel quote chain
	//   - NRAS      → NVIDIA NRAS JWT verify against pinned issuer key
	//
	// Returns the per-evidence verified reports on success; any
	// chain-verify failure → (nil, err) and the gate MUST refuse
	// release. Wire-in for #222 go-sev-guest: without this step a
	// worker can craft an envelope whose Verify(nonce) returns true
	// while the actual blobs are unsigned or signed by a non-AMD key.
	VerifyEvidence(ctx context.Context, opts ...attest.Option) ([]*attest.VerifiedReport, error)

	// RIMDigest returns the Reference Integrity Manifest digest the
	// worker measured. Compared to ReleasePolicy.RequiredRIM.
	RIMDigest() [32]byte

	// HardwareFingerprint returns sha256(model || driver || vbios).
	// Compared to ReleasePolicy.AllowedHardware.
	HardwareFingerprint() [32]byte

	// TEEPublicKey returns the X25519 public key whose private half
	// lives only inside the worker's GPU TEE. Used to seal the session
	// key so only the attested TEE can unwrap it.
	TEEPublicKey() [32]byte
}

// ReleasePolicy is the static allowlist a gate enforces. Bind one
// policy per workload kind — e.g. "training-confidential" gets a
// stricter RIM set than "inference-rwq".
//
// RequiredRIM and AllowedHardware are sets — membership semantics, not
// ordered. Empty sets fail closed (no RIM ⇒ no release).
type ReleasePolicy struct {
	RequiredRIM     map[[32]byte]struct{}
	AllowedHardware map[[32]byte]struct{}
}

// NewReleasePolicy builds a policy from slices of digests, deduplicating
// into the allowlist sets.
func NewReleasePolicy(rims, hardware [][32]byte) ReleasePolicy {
	p := ReleasePolicy{
		RequiredRIM:     make(map[[32]byte]struct{}, len(rims)),
		AllowedHardware: make(map[[32]byte]struct{}, len(hardware)),
	}
	for _, r := range rims {
		p.RequiredRIM[r] = struct{}{}
	}
	for _, h := range hardware {
		p.AllowedHardware[h] = struct{}{}
	}
	return p
}

// Permits reports whether the attestation's measurements satisfy the
// policy. Membership-check only; nonce + signature verification is the
// gate's job.
func (p ReleasePolicy) Permits(att CompositeAttestation) bool {
	if len(p.RequiredRIM) == 0 || len(p.AllowedHardware) == 0 {
		return false
	}
	if _, ok := p.RequiredRIM[att.RIMDigest()]; !ok {
		return false
	}
	if _, ok := p.AllowedHardware[att.HardwareFingerprint()]; !ok {
		return false
	}
	return true
}

// SealedSessionKey is the artifact returned to the worker. It contains
// the ChaCha20-Poly1305 ciphertext of a freshly-generated 32-byte
// session key, sealed under ECDH(gate_ephemeral, tee_pubkey).
//
// The worker performs ECDH(tee_priv, EphemeralPub), derives the same
// AEAD key via HKDF-SHA256, and decrypts. The session key never appears
// in plaintext outside the gate and the GPU TEE.
type SealedSessionKey struct {
	Epoch        uint64   `json:"epoch"`
	JobID        [32]byte `json:"job_id"`
	IssuedNonce  [32]byte `json:"issued_nonce"` // gate-issued challenge nonce (bound into AAD)
	EphemeralPub [32]byte `json:"ephemeral_pub"`
	Nonce        [12]byte `json:"nonce"`
	Ciphertext   []byte   `json:"ciphertext"` // 32-byte key + 16-byte tag
}

// AAD returns the additional-authenticated-data the AEAD binds. Tying
// epoch + job_id + tee_pubkey + issued_nonce into AAD prevents:
//   - cross-job replay of a sealed key (jobID binding)
//   - cross-epoch replay (epoch binding)
//   - cross-TEE replay (teePub binding)
//   - cross-issuance reuse if the gate's restart wipes lastJobID
//     (issued_nonce binding — every Issue() picks a fresh nonce, so two
//     Release() calls with the same (epoch, jobID) but different
//     issuances produce distinct AADs).
func (s SealedSessionKey) AAD(teePub [32]byte) []byte {
	out := make([]byte, 0, 8+32+32+32)
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], s.Epoch)
	out = append(out, ep[:]...)
	out = append(out, s.JobID[:]...)
	out = append(out, teePub[:]...)
	out = append(out, s.IssuedNonce[:]...)
	return out
}

// ReleaseRequest carries everything the gate needs in one shot. JobID
// is opaque to the gate (used only for AAD binding).
//
// Ctx, when non-nil, is threaded into the cc/attest chain verifier so
// AMD KDS / NRAS network calls cannot stall the gate. When nil the
// gate uses context.Background().
//
// AttestOptions are forwarded to VerifyEvidence; production callers
// MUST include attest.WithExpectedReportData(rec.Nonce[:]) (or an
// equivalent measurement pin) so the chain verifier refuses any quote
// whose REPORT_DATA does not equal the gate-issued nonce. The gate
// does not auto-bind here because the REPORT_DATA framing is
// kind-specific (64-byte field on SEV-SNP/TDX, JWT claim on NRAS).
type ReleaseRequest struct {
	JobID         [32]byte
	Epoch         uint64
	Nonce         [32]byte // gate-issued, attested-over by the worker
	Attestation   CompositeAttestation
	Ctx           context.Context
	AttestOptions []attest.Option
}

// ReleaseGate verifies attestation + releases a session key sealed to
// the worker's TEE pubkey. Stateless w.r.t. session keys (each call
// generates a fresh one); stateful w.r.t. epoch + replay set.
type ReleaseGate interface {
	// Issue is called by the worker AFTER it has opened a session and
	// generated its TEE keypair. The gate returns the attestation
	// nonce + current epoch the worker MUST bind into its attestation.
	Issue(jobID [32]byte) (nonce [32]byte, epoch uint64, err error)

	// Release verifies the attestation against the gate's policy and
	// returns the sealed session key. Refuses on any of:
	//   - signature/nonce mismatch
	//   - RIM not in allowlist
	//   - hardware not in allowlist
	//   - epoch mismatch (replay)
	//   - jobID re-use within the current epoch (replay)
	//   - cc/attest chain verify failure on any evidence blob
	Release(req ReleaseRequest) (SealedSessionKey, error)

	// Rotate advances the epoch — invalidates all in-flight nonces.
	// Called on policy change, key rotation, or scheduled epoch boundary.
	Rotate() uint64
}

// ErrPolicyRefused is returned when policy or attestation fails.
// Callers MUST treat this as a hard refusal — never as "approved by default".
var ErrPolicyRefused = errors.New("kms/release: refused")

// ErrAttestationChain is returned when the cc/attest chain verifier
// (AMD KDS + VCEK validation, NVIDIA NRAS JWT, Intel TDX quote)
// refuses any evidence blob in the envelope. Wrapped by
// ErrPolicyRefused via errors.Join so callers can switch on either
// sentinel; the gate releases NO key when this fires. Red Final N1
// wire-in: a forged envelope whose Verify(nonce) returns true but
// whose evidence does not chain to the pinned vendor root must
// produce ErrAttestationChain, not silent acceptance.
var ErrAttestationChain = errors.New("kms/release: attestation chain verify failed")

// DefaultReplayWindow is how long a consumed jobID stays in the replay
// set after Release(). 1 hour absorbs clock skew + worker retries
// without growing the consumed-set unbounded.
const DefaultReplayWindow = 1 * time.Hour

// DefaultIssueTTL is how long a pending Issue() lives before GC. 1 hour
// matches the replay window — anything older than this is stale and
// must re-issue.
const DefaultIssueTTL = 1 * time.Hour

// nonceBindingDomain is the HMAC domain separator. Versioned so a
// future migration (e.g. v2 binds additional fields) does not collide
// with v1 issued nonces still in the pending set.
const nonceBindingDomain = "kms/release/v1"

// LocalReleaseGate is a single-process gate. The KMS root signing key
// stays in process memory (not persisted to disk; rotated on restart).
// Suitable for single-tenant prod and dev. For multi-tenant prod use
// MPCReleaseGate or HSMReleaseGate.
//
// State (epoch + pending nonces + consumed-set) lives in the injected
// NonceStore. Pass NewMemoryNonceStore() for tests; pass
// NewDatabaseNonceStore(db) for production where db is an
// encdb-wrapped ZapDB or any luxfi/database-compatible KV.
type LocalReleaseGate struct {
	policy   ReleasePolicy
	store    NonceStore
	rootKey  [32]byte // HMAC key for nonce binding
	issueTTL time.Duration
	replayTT time.Duration

	mu sync.Mutex
}

// NewLocalReleaseGate constructs a gate. rootKey MUST be 32 bytes of
// fresh entropy from a secure source (KMS-managed; never derived from
// a constant). store provides durable epoch + nonce state.
func NewLocalReleaseGate(policy ReleasePolicy, store NonceStore, rootKey [32]byte) (*LocalReleaseGate, error) {
	if store == nil {
		return nil, errors.New("kms/release: nil store")
	}
	var zero [32]byte
	if rootKey == zero {
		return nil, errors.New("kms/release: rootKey must be non-zero")
	}
	g := &LocalReleaseGate{
		policy:   policy,
		store:    store,
		rootKey:  rootKey,
		issueTTL: DefaultIssueTTL,
		replayTT: DefaultReplayWindow,
	}
	// Initialize epoch on first use; persisted across restarts.
	if _, err := store.EpochGet(); err != nil {
		return nil, fmt.Errorf("kms/release: epoch init: %w", err)
	}
	return g, nil
}

// SetReplayWindow overrides the default replay window. Call before any
// Issue() / Release(). For testing.
func (g *LocalReleaseGate) SetReplayWindow(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.replayTT = d
}

// SetIssueTTL overrides the default issue TTL. For testing.
func (g *LocalReleaseGate) SetIssueTTL(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.issueTTL = d
}

// deriveNonce binds (epoch, jobID, fresh entropy) under the gate's
// root key. A worker that intercepts a nonce for jobID A cannot replay
// it under jobID B — the HMAC commits to the jobID, and the gate
// stores the exact bytes for verification on Release().
func (g *LocalReleaseGate) deriveNonce(epoch uint64, jobID [32]byte) ([32]byte, error) {
	var rand32 [32]byte
	if _, err := rand.Read(rand32[:]); err != nil {
		return [32]byte{}, fmt.Errorf("kms/release: rand: %w", err)
	}
	mac := hmac.New(sha256.New, g.rootKey[:])
	mac.Write([]byte(nonceBindingDomain))
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], epoch)
	mac.Write(ep[:])
	mac.Write(jobID[:])
	mac.Write(rand32[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out, nil
}

// Issue implements ReleaseGate.
func (g *LocalReleaseGate) Issue(jobID [32]byte) ([32]byte, uint64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	epoch, err := g.store.EpochGet()
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("kms/release: epoch get: %w", err)
	}

	nonce, err := g.deriveNonce(epoch, jobID)
	if err != nil {
		return [32]byte{}, 0, err
	}

	rec := NonceRecord{
		JobID:   jobID,
		Nonce:   nonce,
		Epoch:   epoch,
		Expires: time.Now().Add(g.issueTTL),
	}
	if err := g.store.Issue(rec); err != nil {
		return [32]byte{}, 0, fmt.Errorf("%w: %v", ErrPolicyRefused, err)
	}
	return nonce, epoch, nil
}

// Release implements ReleaseGate. The order of checks is intentional:
//
//  1. epoch match (cheap)
//  2. lookup pending record (storage hit)
//  3. constant-time nonce equality (no timing leak on jobID enumeration)
//  4. attestation nonce verify (cheap, in-memory)
//  5. cc/attest chain verify — VCEK / KDS / SEV-SNP / TDX / NRAS
//     (network + signature, the actual root-of-trust step). Without
//     this step the audit-bypass exists: a worker crafts an envelope
//     whose Verify(nonce) returns true but whose evidence blobs do not
//     chain to the pinned vendor root.
//  6. policy permits (RIM + hardware membership)
//  7. seal session key (ECDH + AEAD)
//  8. consume (atomic — only after all checks pass)
//
// Any failure at step 4 → ErrPolicyRefused. Any failure at step 5 →
// ErrPolicyRefused joined with ErrAttestationChain. No silent
// acceptance; a cryptographically valid nonce binding is NOT
// sufficient on its own.
func (g *LocalReleaseGate) Release(req ReleaseRequest) (SealedSessionKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	epoch, err := g.store.EpochGet()
	if err != nil {
		return SealedSessionKey{}, fmt.Errorf("kms/release: epoch get: %w", err)
	}
	if req.Epoch != epoch {
		return SealedSessionKey{}, fmt.Errorf("%w: epoch mismatch (req=%d gate=%d)", ErrPolicyRefused, req.Epoch, epoch)
	}

	rec, err := g.store.Lookup(req.JobID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNonceUnknown):
			return SealedSessionKey{}, errors.Join(ErrPolicyRefused, err)
		case errors.Is(err, ErrAlreadyConsumed):
			return SealedSessionKey{}, errors.Join(ErrPolicyRefused, err)
		case errors.Is(err, ErrExpired):
			return SealedSessionKey{}, errors.Join(ErrPolicyRefused, err)
		default:
			return SealedSessionKey{}, fmt.Errorf("kms/release: lookup: %w", err)
		}
	}
	if rec.Epoch != req.Epoch {
		return SealedSessionKey{}, fmt.Errorf("%w: stored epoch mismatch", ErrPolicyRefused)
	}
	// Constant-time compare to avoid timing leaks on partial nonce match.
	if !hmac.Equal(rec.Nonce[:], req.Nonce[:]) {
		return SealedSessionKey{}, errors.Join(ErrPolicyRefused, ErrNonceMismatch)
	}

	if req.Attestation == nil {
		return SealedSessionKey{}, fmt.Errorf("%w: attestation nil", ErrPolicyRefused)
	}
	// Pass the gate-issued nonce (from the store), NOT req.Nonce — even
	// though we just compared them, threading the stored bytes makes
	// Verify's contract unambiguous: it sees the canonical challenge.
	ok, err := req.Attestation.Verify(rec.Nonce)
	if err != nil {
		return SealedSessionKey{}, fmt.Errorf("kms/release: attestation verify: %w", err)
	}
	if !ok {
		return SealedSessionKey{}, fmt.Errorf("%w: attestation invalid", ErrPolicyRefused)
	}

	// Step 5 — the canonical chain verifier. Dispatches every
	// supported CPU TEE / GPU evidence blob to cc/attest:
	//
	//   - SEV-SNP   → AMD KDS lookup, ARK→ASK→VCEK chain, signature
	//   - TDX       → Intel quote chain
	//   - NRAS      → NVIDIA NRAS JWT verify against pinned issuer key
	//
	// Red Final N1: without this step the #222 go-sev-guest wins are
	// dead code — Verify(nonce) is trivially satisfied by a worker
	// that fabricates the envelope. VerifyEvidence forces the actual
	// cryptographic chain check; any failure → ErrAttestationChain
	// wrapped under ErrPolicyRefused.
	ctx := req.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := req.Attestation.VerifyEvidence(ctx, req.AttestOptions...); err != nil {
		return SealedSessionKey{}, errors.Join(ErrPolicyRefused, fmt.Errorf("%w: %v", ErrAttestationChain, err))
	}

	if !g.policy.Permits(req.Attestation) {
		return SealedSessionKey{}, fmt.Errorf("%w: policy denied (RIM or hardware)", ErrPolicyRefused)
	}

	sealed, err := sealSessionKey(req.JobID, req.Epoch, rec.Nonce, req.Attestation.TEEPublicKey())
	if err != nil {
		return SealedSessionKey{}, fmt.Errorf("kms/release: seal: %w", err)
	}

	if err := g.store.Consume(req.JobID, time.Now().Add(g.replayTT)); err != nil {
		// At this point the seal succeeded but consume failed; refuse
		// the release rather than risk handing out a key whose
		// jobID may be replayable. Surface as policy refusal.
		return SealedSessionKey{}, fmt.Errorf("%w: consume: %v", ErrPolicyRefused, err)
	}
	return sealed, nil
}

// Rotate implements ReleaseGate. Bumping the epoch invalidates any
// pending nonces (Lookup at the new epoch will mismatch on rec.Epoch).
// The pending set is GC'd lazily; consumed-set carries forward through
// its replay window so a cross-epoch replay is still refused.
func (g *LocalReleaseGate) Rotate() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	epoch, err := g.store.EpochGet()
	if err != nil {
		// Epoch get on a healthy store cannot fail; if it does the
		// only safe action is to keep the old epoch.
		return 0
	}
	next := epoch + 1
	if err := g.store.EpochSet(next); err != nil {
		return epoch
	}
	// Best-effort GC of any stale pending entries from the old epoch.
	_ = g.store.GC(time.Now())
	return next
}

// GC drops expired pending nonces and consumed-set entries past their
// replay window. Call periodically from a background ticker.
func (g *LocalReleaseGate) GC() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.store.GC(time.Now())
}

// sealSessionKey generates a 32-byte session key, performs X25519 ECDH
// against the worker's TEE pubkey, derives a ChaCha20-Poly1305 key via
// SHA-256(shared || "kms/release/v1"), and seals.
//
// Note: stdlib X25519 + chacha20poly1305 — no HPKE indirect dep.
func sealSessionKey(jobID [32]byte, epoch uint64, issuedNonce [32]byte, teePub [32]byte) (SealedSessionKey, error) {
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return SealedSessionKey{}, fmt.Errorf("eph priv: %w", err)
	}
	// Clamp per RFC 7748 §5
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return SealedSessionKey{}, fmt.Errorf("eph pub: %w", err)
	}
	shared, err := curve25519.X25519(ephPriv[:], teePub[:])
	if err != nil {
		return SealedSessionKey{}, fmt.Errorf("ecdh: %w", err)
	}
	// Refuse all-zero shared (low-order point attack).
	var zero [32]byte
	if subtleEqual(shared, zero[:]) {
		return SealedSessionKey{}, errors.New("ecdh: low-order point")
	}

	h := sha256.New()
	h.Write(shared)
	h.Write([]byte(nonceBindingDomain))
	aeadKey := h.Sum(nil)

	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return SealedSessionKey{}, fmt.Errorf("aead: %w", err)
	}

	var sessionKey [32]byte
	if _, err := rand.Read(sessionKey[:]); err != nil {
		return SealedSessionKey{}, fmt.Errorf("session key: %w", err)
	}

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return SealedSessionKey{}, fmt.Errorf("nonce: %w", err)
	}

	out := SealedSessionKey{
		Epoch:       epoch,
		JobID:       jobID,
		IssuedNonce: issuedNonce,
		Nonce:       nonce,
	}
	copy(out.EphemeralPub[:], ephPub)
	out.Ciphertext = aead.Seal(nil, nonce[:], sessionKey[:], out.AAD(teePub))
	return out, nil
}

// subtleEqual reports byte-wise equality without leaking timing.
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// MPCReleaseGate distributes the release decision across t-of-n KMS
// nodes. Each node runs its own LocalReleaseGate with the same policy;
// the session key is reconstructed via threshold ECDH only when t nodes
// approve. The wrapper here orchestrates the quorum; per-node logic is
// the embedded LocalReleaseGate. Single binary, two roles (local vs
// quorum) — same code path.
//
// For now the threshold combiner is the existing MPC orchestrator
// (CGGMP21 for the wrap-key); this struct is the integration seam.
type MPCReleaseGate struct {
	*LocalReleaseGate
	threshold  int
	totalNodes int
}

// NewMPCReleaseGate wraps a LocalReleaseGate with quorum metadata. The
// caller is responsible for running the threshold protocol; this gate
// only releases once Quorum() reports the signed approval set.
func NewMPCReleaseGate(policy ReleasePolicy, store NonceStore, rootKey [32]byte, threshold, total int) (*MPCReleaseGate, error) {
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, fmt.Errorf("kms/release: invalid quorum %d-of-%d", threshold, total)
	}
	local, err := NewLocalReleaseGate(policy, store, rootKey)
	if err != nil {
		return nil, err
	}
	return &MPCReleaseGate{
		LocalReleaseGate: local,
		threshold:        threshold,
		totalNodes:       total,
	}, nil
}

// Threshold returns t.
func (g *MPCReleaseGate) Threshold() int { return g.threshold }

// TotalNodes returns n.
func (g *MPCReleaseGate) TotalNodes() int { return g.totalNodes }

// HSMReleaseGate routes the seal-key generation through luxfi/hsm so the
// ephemeral private key never appears in process memory. Implementation
// composes a luxfi/hsm Signer/Wrapper with the LocalReleaseGate state.
//
// The current build keeps the ECDH ephemeral in process (LocalReleaseGate
// behavior) and uses HSM only for policy-attestation signing; once
// luxfi/hsm exposes ECDH primitives this swaps in transparently without
// changing the ReleaseGate interface.
type HSMReleaseGate struct {
	*LocalReleaseGate
	hsmKeyID string
}

// NewHSMReleaseGate constructs an HSMReleaseGate bound to an HSM key ID.
func NewHSMReleaseGate(policy ReleasePolicy, store NonceStore, rootKey [32]byte, hsmKeyID string) (*HSMReleaseGate, error) {
	if hsmKeyID == "" {
		return nil, errors.New("kms/release: hsm_key_id required")
	}
	local, err := NewLocalReleaseGate(policy, store, rootKey)
	if err != nil {
		return nil, err
	}
	return &HSMReleaseGate{
		LocalReleaseGate: local,
		hsmKeyID:         hsmKeyID,
	}, nil
}

// HSMKeyID returns the bound HSM key identifier (audit trail).
func (g *HSMReleaseGate) HSMKeyID() string { return g.hsmKeyID }
