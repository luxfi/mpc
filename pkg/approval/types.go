// Package approval provides ApprovalProvider — a pluggable interface for
// out-of-band executive approval of CanonicalIntents.
//
// Approvals are *separate* from MPC signing. The MPC nodes sign the actual
// chain transaction; ApprovalProvider attests that an authorized human (or
// authorized programmatic key) approved the intent before signing began.
//
// Why separate? An MPC quorum that both *authorizes* and *signs* is one
// compromise away from total custody loss. Out-of-band approvers (Ledger
// Enterprise, hardware-backed WebAuthn, KMS-held keys, Safe multisig) raise
// the bar to "compromise the MPC quorum AND the executive's distinct device".
//
// One way to wire approval:
//
//   intent := intent.New(...)
//   bundle, err := orchestrator.CollectApprovals(ctx, intent, approvers, threshold)
//   // intent.SetApprovals(bundle); MPC signing only proceeds when
//   // bundle has >= threshold valid signatures from required approvers.
package approval

import (
	"context"
	"time"
)

// CanonicalIntent is the contract surface this package needs from
// pkg/intent.CanonicalIntent. Anything that produces a stable digest and
// canonical bytes can be approved. We do not import pkg/intent here —
// that would create a coupling we don't need.
//
// pkg/intent.CanonicalIntent's concrete type satisfies this interface via
// method-set match; callers pass it directly.
type CanonicalIntent interface {
	// Digest returns the canonical 32-byte hash committed to by approvers.
	Digest() [32]byte

	// Bytes returns the canonical serialized intent for re-derivation /
	// audit. Approvers MUST verify Digest() == hash(Bytes()) before signing.
	Bytes() []byte
}

// ApprovalProvider is the pluggable interface every approval backend
// implements. Implementations include cloud KMS, hardware HSMs (Ledger /
// YubiKey / Zymbit), WebAuthn passkeys, EVM Safes, and post-quantum signers.
//
// The provider does *not* manage MPC key shares. It manages an *approval*
// keypair owned by a specific approver (human executive or programmatic
// signer). Compromising this keypair compromises authorization decisions
// only — never the underlying MPC keys.
type ApprovalProvider interface {
	// Provider returns the canonical name (e.g. "ledger-enterprise",
	// "webauthn", "aws-kms"). Used in audit logs and the Approval registry.
	Provider() string

	// GetPublicIdentity returns the approver's PublicIdentity — the public
	// material a verifier needs to validate approvals. ApproverID is the
	// stable identifier (email/DID/owner-arn).
	GetPublicIdentity(ctx context.Context, approverID string) (PublicIdentity, error)

	// ApproveIntent produces an ApprovalSignature for the given intent.
	// For interactive providers (Ledger device, WebAuthn) this BLOCKS until
	// the user taps the device, or the context cancels.
	ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error)

	// VerifyApproval checks that sig was produced by approverID via this
	// provider over the given intent. Returns false on signature mismatch,
	// true on cryptographic match. Errors only on unrecoverable failures
	// (network, malformed key) — a wrong signature is (false, nil).
	VerifyApproval(ctx context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error)
}

// PublicIdentity is the public-facing approver record stored in the keyset
// registry. ApproverID is the stable handle ("ceo@fund.com", DID, KMS ARN);
// PublicKey + Algorithm let any verifier independently validate approvals.
//
// Attestation, when present, carries the vendor attestation chain (e.g.
// Ledger Live attestation, FIDO MDS metadata) — empty by default.
type PublicIdentity struct {
	ApproverID  string `json:"approver_id"`
	Provider    string `json:"provider"`
	PublicKey   []byte `json:"public_key"`
	Algorithm   string `json:"algorithm"`
	Attestation []byte `json:"attestation,omitempty"`
}

// ApprovalSignature is the artifact attached to a CanonicalIntent. It binds
// (approverID, provider, intent_digest) under the approver's keypair so a
// later verifier can prove "this exact human approved this exact intent".
//
// Algorithm carries the signature scheme used so multi-algorithm bundles
// (mixed ECDSA / Ed25519 / ML-DSA) can be verified without external lookup.
type ApprovalSignature struct {
	ApproverID   string    `json:"approver_id"`
	Provider     string    `json:"provider"`
	IntentDigest [32]byte  `json:"intent_digest"`
	Signature    []byte    `json:"signature"`
	Timestamp    time.Time `json:"timestamp"`
	Algorithm    string    `json:"algorithm"`
}

// Algorithm constants for ApprovalSignature.Algorithm and PublicIdentity.Algorithm.
//
// Use the named constants — never raw strings — so a typo at the call site
// becomes a compile error.
const (
	AlgorithmECDSAP256      = "ECDSA-P256"        // generic ECDSA secp256r1, SHA-256
	AlgorithmECDSAsecp256k1 = "ECDSA-secp256k1"   // Ethereum / Bitcoin signatures
	AlgorithmEd25519        = "Ed25519"
	AlgorithmMLDSA65        = "ML-DSA-65"          // FIPS 204, NIST level 3
	AlgorithmSafeContract   = "Safe-execTransaction" // on-chain Safe approval
	AlgorithmWebAuthnES256  = "WebAuthn-ES256"     // CTAP2 ES256 (P-256)
)
