package approval

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SafeMultisigProvider treats a Gnosis Safe (now Safe) execTransaction as
// the approval. The Safe contract enforces N-of-M owner signatures on-chain;
// once `execTransaction` succeeds, that's a cryptographic proof of approval
// by the configured Safe owners.
//
// Layout of an approval bundle for this provider:
//
//   [chainID (8B BE)] [safeAddress (20B)] [safeTxHash (32B)] [execTxHash (32B)]
//
// Verification: a service caller checks
//
//   1. safeTxHash == Safe.getTransactionHash(intent.Bytes() / EIP-712 typed data)
//   2. execTxHash is mined (≥ 1 confirmation) on the chain
//   3. execTxHash receipt logs include `ExecutionSuccess(safeTxHash)`
//
// This package only validates the bundle's *shape* — on-chain confirmation
// is the caller's responsibility (it requires an EVM RPC client we don't
// want as a dep here). Operators must wire a chain client at the API layer.
//
// Configuration:
//
//   chain_id      — decimal chain ID (e.g. "1" mainnet, "42161" arbitrum)
//   safe_address  — 0x-prefixed Safe address (20 bytes)
//
// Approver enrollment: register approverID -> Safe address. One Safe can
// represent any number of logical approvers (each with their own owner key)
// — the Safe quorum *is* the approval threshold, so a single Safe maps to
// approverID = "<org>-treasury-safe".
type SafeMultisigProvider struct {
	chainID     uint64
	safeAddress [20]byte

	mu       sync.RWMutex
	pending  map[string]*pendingSafe
	identity map[string]safeEntry
}

type safeEntry struct {
	SafeAddress [20]byte
	ChainID     uint64
}

type pendingSafe struct {
	intent     CanonicalIntent
	expiresAt  time.Time
	resultCh   chan safeResult
}

type safeResult struct {
	sig ApprovalSignature
	err error
}

func NewSafeMultisig(config map[string]string) (ApprovalProvider, error) {
	if config == nil {
		return nil, errors.New("approval/safe: config required (chain_id, safe_address)")
	}
	chainIDRaw := config["chain_id"]
	if chainIDRaw == "" {
		return nil, errors.New("approval/safe: chain_id required")
	}
	var chainID uint64
	if _, err := fmt.Sscanf(chainIDRaw, "%d", &chainID); err != nil || chainID == 0 {
		return nil, fmt.Errorf("approval/safe: invalid chain_id %q", chainIDRaw)
	}
	addrHex := config["safe_address"]
	addr, err := parseHex20(addrHex)
	if err != nil {
		return nil, fmt.Errorf("approval/safe: %w", err)
	}
	return &SafeMultisigProvider{
		chainID:     chainID,
		safeAddress: addr,
		pending:     make(map[string]*pendingSafe),
		identity:    make(map[string]safeEntry),
	}, nil
}

func (p *SafeMultisigProvider) Provider() string { return "safe-multisig" }

// Enroll registers an approver-to-Safe mapping. Each approverID is the
// logical name (e.g. "treasury-3of5"); the Safe's owner set defines who
// can actually sign. chainID and safeAddress override the provider-level
// config — useful for multi-chain deployments where one provider serves
// several Safes (e.g. one per chain).
func (p *SafeMultisigProvider) Enroll(approverID string, chainID uint64, safeAddressHex string) error {
	addr, err := parseHex20(safeAddressHex)
	if err != nil {
		return fmt.Errorf("approval/safe: enroll: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = safeEntry{
		SafeAddress: addr,
		ChainID:     chainID,
	}
	return nil
}

func (p *SafeMultisigProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		// Default to the provider-level Safe if no per-approver mapping.
		entry = safeEntry{SafeAddress: p.safeAddress, ChainID: p.chainID}
	}
	pub := make([]byte, 28)
	binary.BigEndian.PutUint64(pub[:8], entry.ChainID)
	copy(pub[8:], entry.SafeAddress[:])
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  pub,
		Algorithm:  AlgorithmSafeContract,
	}, nil
}

// SubmitExecution is called by the API once the Safe transaction is mined.
// safeTxHash is the EIP-712 hash of the SafeTx struct; execTxHash is the
// L1 transaction hash carrying the execTransaction call.
//
// In production, the caller MUST verify on-chain that execTxHash succeeded
// and emitted ExecutionSuccess(safeTxHash) before invoking SubmitExecution.
// This package does NOT do that — it only assembles the bundle.
func (p *SafeMultisigProvider) SubmitExecution(_ context.Context, sessionID string, safeTxHash, execTxHash [32]byte) (ApprovalSignature, error) {
	p.mu.Lock()
	pending, ok := p.pending[sessionID]
	if !ok {
		p.mu.Unlock()
		return ApprovalSignature{}, errors.New("approval/safe: no pending session")
	}
	if time.Now().After(pending.expiresAt) {
		delete(p.pending, sessionID)
		p.mu.Unlock()
		return ApprovalSignature{}, errors.New("approval/safe: session expired")
	}
	delete(p.pending, sessionID)
	p.mu.Unlock()

	approverID, _, err := splitWebAuthnSession(sessionID)
	if err != nil {
		return ApprovalSignature{}, err
	}
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	if !ok {
		entry = safeEntry{SafeAddress: p.safeAddress, ChainID: p.chainID}
	}
	p.mu.RUnlock()

	bundle := encodeSafeBundle(entry.ChainID, entry.SafeAddress, safeTxHash, execTxHash)
	digest := pending.intent.Digest()
	sig := ApprovalSignature{
		ApproverID:   approverID,
		Provider:     p.Provider(),
		IntentDigest: digest,
		Signature:    bundle,
		Timestamp:    time.Now().UTC(),
		Algorithm:    AlgorithmSafeContract,
	}
	select {
	case pending.resultCh <- safeResult{sig: sig}:
	default:
	}
	return sig, nil
}

// IssueChallenge starts a Safe approval session. The caller is responsible
// for proposing the corresponding execTransaction on-chain (typically via
// Safe Transaction Service or the Safe SDK) — this provider only tracks
// the resulting safeTxHash / execTxHash bundle.
func (p *SafeMultisigProvider) IssueChallenge(_ context.Context, approverID string, intent CanonicalIntent) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	digest := intent.Digest()
	sessionID := approverID + "/" + hexEncode(digest[:])
	p.pending[sessionID] = &pendingSafe{
		intent:    intent,
		expiresAt: time.Now().Add(15 * time.Minute), // longer for on-chain ceremonies
		resultCh:  make(chan safeResult, 1),
	}
	return sessionID, nil
}

// ApproveIntent issues a session and blocks waiting for SubmitExecution.
// The caller (orchestrator) typically uses the explicit session API
// because Safe ceremonies span minutes-to-hours.
func (p *SafeMultisigProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	sessionID, err := p.IssueChallenge(ctx, approverID, intent)
	if err != nil {
		return ApprovalSignature{}, err
	}
	p.mu.Lock()
	pending := p.pending[sessionID]
	p.mu.Unlock()
	if pending == nil {
		return ApprovalSignature{}, errors.New("approval/safe: pending session lost")
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

func (p *SafeMultisigProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	if sig.Provider != p.Provider() || sig.Algorithm != AlgorithmSafeContract {
		return false, nil
	}
	digest := intent.Digest()
	if digest != sig.IntentDigest {
		return false, nil
	}
	chainID, safeAddr, _, _, err := decodeSafeBundle(sig.Signature)
	if err != nil {
		return false, nil
	}
	p.mu.RLock()
	entry, ok := p.identity[sig.ApproverID]
	p.mu.RUnlock()
	if !ok {
		entry = safeEntry{SafeAddress: p.safeAddress, ChainID: p.chainID}
	}
	if chainID != entry.ChainID {
		return false, nil
	}
	if safeAddr != entry.SafeAddress {
		return false, nil
	}
	// Note: this verifier returns true once the bundle structurally matches
	// the enrolled Safe. The caller MUST independently verify execTxHash on
	// chain — see SubmitExecution doc. Not having an EVM client in this
	// package is deliberate; that's a wiring concern at the API layer.
	return true, nil
}

func encodeSafeBundle(chainID uint64, safeAddr [20]byte, safeTxHash, execTxHash [32]byte) []byte {
	out := make([]byte, 8+20+32+32)
	binary.BigEndian.PutUint64(out[:8], chainID)
	copy(out[8:28], safeAddr[:])
	copy(out[28:60], safeTxHash[:])
	copy(out[60:92], execTxHash[:])
	return out
}

func decodeSafeBundle(b []byte) (chainID uint64, safeAddr [20]byte, safeTxHash [32]byte, execTxHash [32]byte, err error) {
	if len(b) != 92 {
		err = fmt.Errorf("approval/safe: bundle wrong length: %d", len(b))
		return
	}
	chainID = binary.BigEndian.Uint64(b[:8])
	copy(safeAddr[:], b[8:28])
	copy(safeTxHash[:], b[28:60])
	copy(execTxHash[:], b[60:92])
	return
}

func parseHex20(s string) ([20]byte, error) {
	var out [20]byte
	if len(s) == 42 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if len(s) != 40 {
		return out, fmt.Errorf("hex address must be 20 bytes (40 hex chars), got %d", len(s))
	}
	for i := 0; i < 20; i++ {
		hi, ok1 := fromHexNibble(s[2*i])
		lo, ok2 := fromHexNibble(s[2*i+1])
		if !ok1 || !ok2 {
			return out, fmt.Errorf("invalid hex byte at offset %d", 2*i)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func fromHexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}
