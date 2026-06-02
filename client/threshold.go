// Package client — canonical client interface for Lux MPC.
//
//	import mpc "github.com/luxfi/mpc/client"
//	var t mpc.Threshold = luxmpc.NewThreshold(cfg)

package client

import (
	"context"
	"errors"
)

// Typed errors. Callers branch via errors.Is.
var (
	// ErrIdempotencyConflict is returned when a Sign call reuses an
	// IdempotencyKey from a prior session whose canonical request hash
	// differs from this one. Implementations MUST never return a
	// cached signature when the request differs — that is a signing
	// oracle.
	ErrIdempotencyConflict = errors.New("mpc: idempotency conflict")

	// ErrIdempotencyKeyRequired is returned when Sign is called with
	// an empty IdempotencyKey.
	ErrIdempotencyKeyRequired = errors.New("mpc: idempotency key required")

	// ErrComplianceRejected is returned when the backend's compliance
	// ruleset refuses the signature. The wrapped *ComplianceRejection
	// names the gate.
	ErrComplianceRejected = errors.New("mpc: compliance rejected")

	// ErrSessionNotFound is returned by GetSession / Cancel for an
	// unknown session id, OR for a session that does not belong to the
	// caller's org (the implementation MUST NOT distinguish the two —
	// disclosing existence is an enumeration oracle).
	ErrSessionNotFound = errors.New("mpc: session not found")
)

// Threshold is the compliance-gated threshold-signature surface.
// Every custody mutation (mint, burn, transfer, settle) signs through
// Threshold.Sign — there is no direct path to the MPC backend.
//
// Identity: the request's UserID + OrgID MUST be derived from the
// validated bearer-auth Claims attached to ctx. Implementations MUST
// refuse a call whose request UserID/OrgID disagrees with ctx Claims.
type Threshold interface {
	// Kind reports the backend identifier
	// (ta-cggmp21 | lit-protocol | fireblocks-mpc | coinbase-custody).
	Kind() string

	// Sign requests a threshold signature.
	//
	// Idempotency contract:
	//   1. IdempotencyKey is required. Empty → ErrIdempotencyKeyRequired.
	//   2. The implementation MUST compute CanonicalHash(SignRequest)
	//      over every request field except IdempotencyKey itself, and
	//      bind the cached session to that hash.
	//   3. A second call with the same IdempotencyKey and the same
	//      CanonicalHash returns the cached SignResult.
	//   4. A second call with the same IdempotencyKey but a different
	//      CanonicalHash returns ErrIdempotencyConflict. NO signing.
	//
	// Compliance contract:
	//   The implementation MUST re-derive the on-chain payload hash
	//   from (Intent, WalletID, Asset, Amount, ChainID) and compare to
	//   the caller-supplied PayloadHash. Mismatch → reject with
	//   ErrPayloadMismatch. This prevents a caller from describing a
	//   "$10 settle" while signing a "$100M withdraw" hash.
	Sign(ctx context.Context, req SignRequest) (*SignResult, error)

	// GetSession returns the current state of a signature session
	// belonging to the caller's org. Unknown ids and cross-org ids
	// return ErrSessionNotFound indistinguishably.
	GetSession(ctx context.Context, sessionID string) (*SignSession, error)

	// Cancel cancels a pending session belonging to the caller's org.
	//
	// Scoping (MUST be enforced by the implementation):
	//   - Derive orgID from ctx Claims; the caller does not supply it.
	//   - SELECT-FOR-UPDATE the session row and verify session.org_id ==
	//     ctx.OrgID before transitioning. Mismatch returns
	//     ErrSessionNotFound — the same opaque response as a truly
	//     unknown id, so a cross-org enumeration cannot distinguish
	//     "exists, not yours" from "does not exist".
	//   - The session-state transition (pending → cancelled) MUST be a
	//     row-level CAS with the org predicate inside the WHERE so a
	//     concurrent legitimate cancel from the right org cannot lose
	//     to a spoofed cross-org call.
	//
	// Idempotent on already-cancelled sessions for the SAME org; cross-
	// org cancellation returns ErrSessionNotFound even if the session
	// is already cancelled (no oracle leak via repeat-cancel semantics).
	Cancel(ctx context.Context, sessionID string) error
}

// SignRequest is the caller-side payload.
//
// UserID and OrgID are RESERVED for the implementation to populate
// from ctx Claims. Callers SHOULD leave them empty; if set, the
// implementation MUST verify they match ctx Claims and reject on
// mismatch.
type SignRequest struct {
	// UserID + OrgID are server-populated from ctx Claims.
	UserID, OrgID string

	// Intent: settle_trade | swap_dex | mint | burn | withdraw |
	// redeem | corporate_action.
	Intent string
	// WalletID is the provider_wallet_id from custody_wallets.
	WalletID string
	// Asset is the token symbol (BTC, USDL, ETH, ...).
	Asset string
	// Amount is the human-readable string.
	Amount string
	// ChainID is the EIP-155 chain id (or chain-specific identifier
	// for non-EVM keys).
	ChainID int
	// PayloadHash is the 32-byte hex of the tx payload. The
	// implementation MUST re-derive from the other request fields and
	// reject mismatch.
	PayloadHash string
	// KeyType: secp256k1 | ed25519 | sr25519 | mldsa65.
	KeyType string
	// IdempotencyKey is required.
	IdempotencyKey string
	// TradeID is optional context for settle_trade.
	TradeID string
}

// ComplianceRejection details which compliance gate refused a Sign call.
type ComplianceRejection struct {
	// Reason: sanctions | velocity | blocklist | manual_review |
	// key_disabled | tenant_disabled | payload_mismatch.
	Reason string
	// ApprovalID is the audit row id; appears in operator dashboards.
	ApprovalID string
}

func (r *ComplianceRejection) Error() string { return "mpc: " + r.Reason }

// SignResult is the immediate response.
type SignResult struct {
	SessionID string
	Signature []byte
	// Status: pending | signed.
	Status     string
	ApprovalID string
}

// SignSession is the poll response.
type SignSession struct {
	SessionID  string
	Status     string // pending | signed | rejected | cancelled
	Signature  []byte
	ApprovalID string
	// Reason populated when Status=rejected. See ComplianceRejection.
	Reason string
}
