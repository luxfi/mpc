// Sign orchestration gate — the per-node policy verification step that
// runs before any partial signature share is produced.
//
// The orchestrator is the integration point for the
// "MPC node signs only if it independently verifies the policy bundle"
// control. Every signing entry point — CGGMP21, FROST, LSS, BLS,
// SR25519 — must call SignGate.AuthorizeSign before its session emits
// a share. Failure FAILS CLOSED: no fallback to "trust the coordinator".
//
// SignGate is intentionally protocol-agnostic. It does not look at
// curves, parties, or message hashes. Its only job is to convert a
// CanonicalIntent into either:
//   - a positive NodeAttestation that authorizes signing this digest
//   - an error that aborts the sign and writes a rejection attestation
//     to the audit log.
//
// The actual MPC signing protocols continue to operate in pkg/mpc as
// before; they simply now have a precondition that must succeed.
package mpc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/mpc/pkg/intent"
	"github.com/luxfi/mpc/pkg/policy"
	"github.com/luxfi/mpc/pkg/scheduler"
)

// AttestationSink persists node attestations (positive or negative) to
// the audit log. The persistence is deliberately separate from the gate
// so the gate has no I/O failure modes that mask policy decisions.
//
// A best-effort sink: failure to persist an attestation must not allow
// signing to proceed — see SignGate.AuthorizeSign for the ordering.
type AttestationSink interface {
	Record(ctx context.Context, att intent.NodeAttestation) error
}

// noopAttestationSink discards attestations. Used when no sink is
// configured (development only); production wiring must supply a real
// sink that writes to the durable audit log.
type noopAttestationSink struct{}

func (noopAttestationSink) Record(_ context.Context, _ intent.NodeAttestation) error { return nil }

// memAttestationSink keeps attestations in memory. Suitable for e2e
// tests that assert audit records.
type memAttestationSink struct {
	mu  sync.Mutex
	all []intent.NodeAttestation
}

// NewMemAttestationSink returns an in-memory sink. Test-only.
func NewMemAttestationSink() *memAttestationSink {
	return &memAttestationSink{}
}

func (m *memAttestationSink) Record(_ context.Context, att intent.NodeAttestation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.all = append(m.all, att)
	return nil
}

// All returns a snapshot of recorded attestations.
func (m *memAttestationSink) All() []intent.NodeAttestation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]intent.NodeAttestation, len(m.all))
	copy(out, m.all)
	return out
}

// SignGate is the per-node authorization gate. One instance per MPC
// node, holding the node's identity key and the LocalVerifier wired
// to that node's copy of the policy + approval keyset.
//
// Scheduler + Worker are optional. When Scheduler is non-nil, the gate
// runs scheduler.Eligible(Worker, ci.PolicyID) BEFORE the policy
// verifier. A scheduler refusal short-circuits the policy check and
// records a reject attestation with reason="scheduler: ...". This is
// how confidential-compute trust posture (TrustGPU, IOPrivateLane,
// approved kernel roots, attested CPU+GPU) is enforced at sign time.
//
// Scheduler == nil keeps the original behavior (legacy deployments
// that have not adopted workload-policy yet). One MPC binary, two
// modes — but the trust-posture-enforced path is the default whenever
// the operator wires a PolicySource into the daemon.
type SignGate struct {
	NodeID    string
	NodeKey   ed25519.PrivateKey
	Verifier  *policy.LocalVerifier
	Attest    AttestationSink
	Scheduler *scheduler.Scheduler // optional; nil = no trust-posture gate
	Worker    scheduler.Worker     // this node's attested posture
}

// NewSignGate constructs a SignGate. nodeKey is the node's Ed25519
// identity key (also used as PoA validator key in the consensus
// transport). verifier is the per-node policy verifier. sink may be
// nil (a noop sink will be used).
func NewSignGate(nodeID string, nodeKey ed25519.PrivateKey, verifier *policy.LocalVerifier, sink AttestationSink) *SignGate {
	if sink == nil {
		sink = noopAttestationSink{}
	}
	return &SignGate{
		NodeID:   nodeID,
		NodeKey:  nodeKey,
		Verifier: verifier,
		Attest:   sink,
	}
}

// WithScheduler wires the workload-policy gate into the SignGate.
// sch resolves WorkloadPolicy by intent.PolicyID; w is this node's
// attested posture (populated from the NVIDIA composite attestation
// and the SEV-SNP/TDX quote). Returns g for chaining.
//
// Calling WithScheduler is the single switch that turns on
// confidential-compute enforcement for this node. There is no
// "best effort" mode — once on, fail-closed.
func (g *SignGate) WithScheduler(sch *scheduler.Scheduler, w scheduler.Worker) *SignGate {
	g.Scheduler = sch
	g.Worker = w
	return g
}

// ErrSignBlocked is returned by AuthorizeSign when policy verification
// fails. The caller (sign session) MUST abort and not produce a share.
var ErrSignBlocked = errors.New("sign: blocked by per-node policy gate")

// AuthorizeSign runs the per-node verifier on ci. On success, returns
// a signed positive NodeAttestation that authorizes the sign. On
// failure, records a rejection attestation and returns
// ErrSignBlocked (wrapped with the underlying cause).
//
// Ordering: the rejection attestation is recorded BEFORE the error
// returns, so even if the caller crashes, the audit record exists.
//
// The returned attestation should be appended to ci.NodeAttestations
// before the partial signature share is broadcast.
func (g *SignGate) AuthorizeSign(ctx context.Context, ci *intent.CanonicalIntent) (intent.NodeAttestation, error) {
	if g == nil || g.Verifier == nil {
		return intent.NodeAttestation{}, errors.New("sign: gate not configured")
	}
	if ci == nil {
		return intent.NodeAttestation{}, errors.New("sign: nil intent")
	}

	// Stage 1 — workload-policy gate (scheduler). Runs first so a node
	// with an inadequate trust posture rejects BEFORE any approval-keyset
	// or policy-bundle work. ci.PolicyID is the canonical workload key.
	//
	// When Scheduler is nil, the stage is skipped entirely — no
	// behavior change for legacy callers.
	var verifyErr error
	if g.Scheduler != nil {
		if elig := g.Scheduler.Eligible(g.Worker, ci.PolicyID); elig != nil {
			verifyErr = fmt.Errorf("scheduler: %w", elig)
		}
	}

	// Stage 2 — per-node policy verifier. Skipped only if the scheduler
	// already rejected; otherwise both checks must pass.
	if verifyErr == nil {
		verifyErr = g.Verifier.Verify(ctx, ci)
	}

	// Build the attestation regardless of outcome — both positive and
	// negative attestations are non-repudiable evidence.
	att, attErr := g.Verifier.AttestationFor(ci, g.NodeID, g.NodeKey, verifyErr)
	if attErr != nil {
		return intent.NodeAttestation{}, fmt.Errorf("sign: attest: %w", attErr)
	}

	// Persist the attestation. Any sink error is treated as a hard
	// failure so we never sign without an audit record.
	if recErr := g.Attest.Record(ctx, att); recErr != nil {
		return intent.NodeAttestation{}, fmt.Errorf("sign: audit record: %w", recErr)
	}

	if verifyErr != nil {
		// Wrap BOTH ErrSignBlocked and the underlying error so callers
		// can use errors.Is() against either layer. ErrInsufficientTrust
		// (from the scheduler) propagates through this join.
		return att, errors.Join(ErrSignBlocked, verifyErr)
	}
	return att, nil
}

// AuthorizeAndDigest is a convenience wrapper that runs the gate and
// returns the canonical digest the underlying signing protocol must
// sign over. This is the value the threshold scheme should use as its
// message hash — derived deterministically from the intent body.
//
// Returning the digest from a single call ensures the caller can never
// accidentally sign over a different value than what was authorized.
func (g *SignGate) AuthorizeAndDigest(ctx context.Context, ci *intent.CanonicalIntent) ([32]byte, intent.NodeAttestation, error) {
	att, err := g.AuthorizeSign(ctx, ci)
	if err != nil {
		return [32]byte{}, att, err
	}
	digest, derr := ci.Digest()
	if derr != nil {
		return [32]byte{}, att, derr
	}
	return digest, att, nil
}
