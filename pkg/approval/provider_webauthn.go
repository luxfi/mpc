package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	mpcwebauthn "github.com/luxfi/mpc/pkg/webauthn"
)

// WebAuthnProvider implements ApprovalProvider for FIDO2 / WebAuthn
// authenticators (passkeys, YubiKeys, platform authenticators).
//
// WebAuthn is a *multi-step* ceremony: the server issues a challenge, the
// authenticator signs it, the client returns the assertion. The synchronous
// ApproveIntent contract requires that all three happen during the call.
//
// We bridge this with a small in-memory pending-challenge map: ApproveIntent
// issues a challenge, blocks on a channel, and unblocks when the API
// completes the ceremony via SubmitAssertion. Callers that don't want to
// block can use IssueChallenge / SubmitAssertion explicitly — the API's
// `/v1/approval/intent/{id}/cast` route does this.
//
// Configuration:
//
//	rpid     — Relying Party ID (e.g. "approvals.fund.com"). Required.
//	origins  — comma-separated allowed origins (e.g. "https://approvals.fund.com").
//	           In production, MUST be HTTPS.
//	timeout  — challenge TTL (default 5m). Override with "300s" / "5m".
//
// HTTPS enforcement: NewWebAuthn requires HTTPS origins unless MPC_ENV=dev.
type WebAuthnProvider struct {
	rpID           string
	allowedOrigins map[string]bool
	timeout        time.Duration

	mu       sync.Mutex
	identity map[string]webauthnEntry
	pending  map[string]*pendingWebAuthn
}

type webauthnEntry struct {
	CredentialID       string // base64url-encoded WebAuthn credential ID
	PubKey             *ecdsa.PublicKey
	PubKeyUncompressed []byte // 65-byte 0x04||X||Y
}

type pendingWebAuthn struct {
	intent    CanonicalIntent
	challenge []byte // 32 random bytes; binds to intent.Digest()
	expiresAt time.Time
	resultCh  chan webauthnResult
}

type webauthnResult struct {
	sig ApprovalSignature
	err error
}

// NewWebAuthn constructs a WebAuthn ApprovalProvider.
func NewWebAuthn(config map[string]string) (ApprovalProvider, error) {
	if config == nil {
		return nil, errors.New("approval/webauthn: config required (rpid, origins)")
	}
	rpID := config["rpid"]
	if rpID == "" {
		return nil, errors.New("approval/webauthn: rpid required")
	}
	originsRaw := config["origins"]
	if originsRaw == "" {
		return nil, errors.New("approval/webauthn: origins required (comma-separated)")
	}
	allowed := map[string]bool{}
	for _, o := range splitCommaTrim(originsRaw) {
		if !isHTTPSOrDev(o) {
			return nil, fmt.Errorf("approval/webauthn: origin %q must be HTTPS in production (set MPC_ENV=dev to permit http://localhost)", o)
		}
		allowed[o] = true
	}
	timeout := 5 * time.Minute
	if tRaw := config["timeout"]; tRaw != "" {
		t, err := time.ParseDuration(tRaw)
		if err != nil {
			return nil, fmt.Errorf("approval/webauthn: parse timeout: %w", err)
		}
		timeout = t
	}
	return &WebAuthnProvider{
		rpID:           rpID,
		allowedOrigins: allowed,
		timeout:        timeout,
		identity:       make(map[string]webauthnEntry),
		pending:        make(map[string]*pendingWebAuthn),
	}, nil
}

func (p *WebAuthnProvider) Provider() string { return "webauthn" }

// Enroll registers an approver's WebAuthn credential. publicKey is the raw
// 65-byte uncompressed P-256 point (0x04||X||Y) extracted from the
// attestation object during the WebAuthn create ceremony.
func (p *WebAuthnProvider) Enroll(approverID, credentialID string, publicKey []byte) error {
	if len(publicKey) != 65 || publicKey[0] != 0x04 {
		return errors.New("approval/webauthn: public key must be 65-byte uncompressed P-256")
	}
	pub, err := mpcwebauthn.ParseUncompressedP256(base64.StdEncoding.EncodeToString(publicKey))
	if err != nil {
		return fmt.Errorf("approval/webauthn: parse public key: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = webauthnEntry{
		CredentialID:       credentialID,
		PubKey:             pub,
		PubKeyUncompressed: publicKey,
	}
	return nil
}

func (p *WebAuthnProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/webauthn: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyUncompressed,
		Algorithm:  AlgorithmWebAuthnES256,
	}, nil
}

// IssueChallenge produces a WebAuthn challenge bound to the intent digest.
// The challenge is `intent.Digest()` directly — no extra randomness is
// required because the digest already commits to the full intent. The
// browser-side WebAuthn client will sign over `authData || SHA256(clientData)`
// where clientData.challenge == base64url(challenge).
//
// Returns a sessionID the API uses to track this pending approval.
func (p *WebAuthnProvider) IssueChallenge(_ context.Context, approverID string, intent CanonicalIntent) (sessionID string, challenge []byte, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.identity[approverID]; !ok {
		return "", nil, fmt.Errorf("approval/webauthn: approver %q not enrolled", approverID)
	}
	digest := intent.Digest()
	chal := make([]byte, 32)
	copy(chal, digest[:])
	sessionID = approverID + "/" + base64.RawURLEncoding.EncodeToString(digest[:])
	p.pending[sessionID] = &pendingWebAuthn{
		intent:    intent,
		challenge: chal,
		expiresAt: time.Now().Add(p.timeout),
		resultCh:  make(chan webauthnResult, 1),
	}
	return sessionID, chal, nil
}

// SubmitAssertion is called by the API when the browser returns the
// WebAuthn assertion bundle. It verifies the assertion against the stored
// challenge + public key, and unblocks any waiting ApproveIntent caller.
func (p *WebAuthnProvider) SubmitAssertion(_ context.Context, sessionID string, clientDataJSONB64, authDataB64, signatureB64 string) (ApprovalSignature, error) {
	p.mu.Lock()
	pending, ok := p.pending[sessionID]
	if !ok {
		p.mu.Unlock()
		return ApprovalSignature{}, errors.New("approval/webauthn: no pending challenge for session")
	}
	if time.Now().After(pending.expiresAt) {
		delete(p.pending, sessionID)
		p.mu.Unlock()
		return ApprovalSignature{}, errors.New("approval/webauthn: challenge expired")
	}
	approverID, _, err := splitWebAuthnSession(sessionID)
	if err != nil {
		p.mu.Unlock()
		return ApprovalSignature{}, err
	}
	entry, ok := p.identity[approverID]
	if !ok {
		p.mu.Unlock()
		return ApprovalSignature{}, fmt.Errorf("approval/webauthn: approver %q not enrolled", approverID)
	}
	pubB64 := base64.StdEncoding.EncodeToString(entry.PubKeyUncompressed)
	p.mu.Unlock()

	out, err := mpcwebauthn.Verify(&mpcwebauthn.Opts{
		Ceremony:          mpcwebauthn.CeremonyGet,
		ExpectedChallenge: pending.challenge,
		AllowedOrigins:    p.allowedOrigins,
		RPID:              p.rpID,
		RequireUP:         true,
		RequireUV:         true,
		PublicKeyB64:      pubB64,
		ClientDataJSONB64: clientDataJSONB64,
		AuthDataB64:       authDataB64,
		SignatureB64:      signatureB64,
	})
	if err != nil {
		// On verify failure, signal failure to any waiter and remove pending.
		p.mu.Lock()
		delete(p.pending, sessionID)
		p.mu.Unlock()
		select {
		case pending.resultCh <- webauthnResult{err: err}:
		default:
		}
		return ApprovalSignature{}, err
	}
	if !out.SignedOK {
		p.mu.Lock()
		delete(p.pending, sessionID)
		p.mu.Unlock()
		return ApprovalSignature{}, errors.New("approval/webauthn: assertion did not produce a verified signature")
	}

	// Build the canonical ApprovalSignature. The signature stored is the
	// concatenation of (authData, clientDataJSON, sig) base64-encoded —
	// future verifiers can re-run the WebAuthn pipeline. We also store
	// the raw assertion sig so simple verifiers can compare against the
	// stored public key directly.
	digest := pending.intent.Digest()
	sigBytes, err := base64.URLEncoding.DecodeString(signatureB64)
	if err != nil {
		if alt, alterr := base64.RawURLEncoding.DecodeString(signatureB64); alterr == nil {
			sigBytes = alt
		} else {
			return ApprovalSignature{}, errors.New("approval/webauthn: invalid signature encoding")
		}
	}
	clientData, _ := base64.URLEncoding.DecodeString(clientDataJSONB64)
	if len(clientData) == 0 {
		clientData, _ = base64.RawURLEncoding.DecodeString(clientDataJSONB64)
	}
	authData, _ := base64.URLEncoding.DecodeString(authDataB64)
	if len(authData) == 0 {
		authData, _ = base64.RawURLEncoding.DecodeString(authDataB64)
	}
	bundled := encodeWebAuthnBundle(authData, clientData, sigBytes)
	approval := ApprovalSignature{
		ApproverID:   approverID,
		Provider:     p.Provider(),
		IntentDigest: digest,
		Signature:    bundled,
		Timestamp:    time.Now().UTC(),
		Algorithm:    AlgorithmWebAuthnES256,
	}

	p.mu.Lock()
	delete(p.pending, sessionID)
	p.mu.Unlock()
	select {
	case pending.resultCh <- webauthnResult{sig: approval}:
	default:
	}
	return approval, nil
}

// ApproveIntent issues a challenge and blocks waiting for SubmitAssertion.
// API endpoints typically use IssueChallenge + the explicit ceremony
// instead — ApproveIntent is for orchestrator integration where the
// orchestrator manages the timeout via context.
func (p *WebAuthnProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	sessionID, _, err := p.IssueChallenge(ctx, approverID, intent)
	if err != nil {
		return ApprovalSignature{}, err
	}
	p.mu.Lock()
	pending := p.pending[sessionID]
	p.mu.Unlock()
	if pending == nil {
		return ApprovalSignature{}, errors.New("approval/webauthn: pending session lost")
	}

	select {
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.pending, sessionID)
		p.mu.Unlock()
		return ApprovalSignature{}, ctx.Err()
	case res := <-pending.resultCh:
		if res.err != nil {
			return ApprovalSignature{}, res.err
		}
		return res.sig, nil
	}
}

func (p *WebAuthnProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	if sig.Provider != p.Provider() || sig.Algorithm != AlgorithmWebAuthnES256 {
		return false, nil
	}
	digest := intent.Digest()
	if digest != sig.IntentDigest {
		return false, nil
	}
	authData, clientData, sigBytes, err := decodeWebAuthnBundle(sig.Signature)
	if err != nil {
		return false, nil
	}
	p.mu.Lock()
	entry, ok := p.identity[sig.ApproverID]
	p.mu.Unlock()
	if !ok {
		return false, nil
	}
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	signedHash := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(entry.PubKey, signedHash[:], sigBytes), nil
}
