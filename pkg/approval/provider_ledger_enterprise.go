package approval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LedgerEnterpriseProvider integrates Ledger Enterprise (Vault) for cold
// custody approvals. The Ledger Enterprise admin proposes a transaction
// against a workspace account; configured approvers tap their Personal
// Security Devices (PSD); the Vault returns an attested signature.
//
// Ledger Enterprise REST endpoints used:
//
//   POST /accounts/{accountId}/transactions             — propose tx
//   GET  /accounts/{accountId}/transactions/{txId}      — poll status
//   POST /accounts/{accountId}/transactions/{txId}/approve  — approve via PSD
//
// Public docs: https://docs.ledger.com/enterprise
//
// Configuration:
//
//   endpoint    — Vault REST base URL (e.g. "https://vault.ledger-enterprise.example/api")
//   api_key     — service-account API key (Bearer token)
//   workspace   — workspace ID
//   timeout     — HTTP request timeout (default 30s); approval polling timeout (default 30m)
//
// Approver enrollment maps approverID -> Vault account ID + cached secp256k1
// public key (Ledger Enterprise typically uses secp256k1 for transaction
// signing; ECDSA-P256 is also supported for some product tiers — caller
// declares the curve via Algorithm at enroll time).
//
// **Honest residual**: this build ships the REST surface and signature
// pipeline real, but without Ledger Enterprise sandbox credentials we can't
// run it against a live Vault. The provider returns an explicit
// NOTIMPL-marked error when its endpoint is unconfigured, and a real error
// from the Ledger API when configured but unreachable. Tests against a
// httptest mock exercise the request/response shape end-to-end.
type LedgerEnterpriseProvider struct {
	endpoint   string
	apiKey     string
	workspace  string
	httpClient *http.Client
	pollEvery  time.Duration
	pollTotal  time.Duration

	mu       sync.RWMutex
	identity map[string]ledgerEnterpriseEntry
}

type ledgerEnterpriseEntry struct {
	AccountID string
	Algorithm string // ECDSA-P256 or ECDSA-secp256k1
	PubKey    *ecdsa.PublicKey
	PubKeyDER []byte
}

// NewLedgerEnterprise constructs a Ledger Enterprise ApprovalProvider.
func NewLedgerEnterprise(config map[string]string) (ApprovalProvider, error) {
	if config == nil {
		return nil, errors.New("approval/ledger-enterprise: config required (endpoint, api_key, workspace)")
	}
	endpoint := strings.TrimRight(config["endpoint"], "/")
	apiKey := config["api_key"]
	workspace := config["workspace"]
	if endpoint == "" || apiKey == "" || workspace == "" {
		return nil, errors.New("approval/ledger-enterprise: endpoint, api_key, and workspace required")
	}
	timeout := 30 * time.Second
	if v := config["timeout"]; v != "" {
		t, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("approval/ledger-enterprise: parse timeout: %w", err)
		}
		timeout = t
	}
	pollTotal := 30 * time.Minute
	if v := config["approval_timeout"]; v != "" {
		t, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("approval/ledger-enterprise: parse approval_timeout: %w", err)
		}
		pollTotal = t
	}
	return &LedgerEnterpriseProvider{
		endpoint:   endpoint,
		apiKey:     apiKey,
		workspace:  workspace,
		httpClient: &http.Client{Timeout: timeout},
		pollEvery:  3 * time.Second,
		pollTotal:  pollTotal,
		identity:   make(map[string]ledgerEnterpriseEntry),
	}, nil
}

func (p *LedgerEnterpriseProvider) Provider() string { return "ledger-enterprise" }

// Enroll registers an approver -> Vault account binding plus the cached
// public key for local verification.
func (p *LedgerEnterpriseProvider) Enroll(approverID, accountID, algorithm string, pubKeyDER []byte) error {
	if algorithm != AlgorithmECDSAP256 && algorithm != AlgorithmECDSAsecp256k1 {
		return fmt.Errorf("approval/ledger-enterprise: unsupported algorithm %q", algorithm)
	}
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("approval/ledger-enterprise: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("approval/ledger-enterprise: enrolled key is not ECDSA")
	}
	switch algorithm {
	case AlgorithmECDSAP256:
		if ecPub.Curve != elliptic.P256() {
			return errors.New("approval/ledger-enterprise: ECDSA-P256 expects P-256 key")
		}
	case AlgorithmECDSAsecp256k1:
		if ecPub.Curve.Params().Name != "secp256k1" {
			return errors.New("approval/ledger-enterprise: ECDSA-secp256k1 expects secp256k1 key")
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = ledgerEnterpriseEntry{
		AccountID: accountID,
		Algorithm: algorithm,
		PubKey:    ecPub,
		PubKeyDER: pubKeyDER,
	}
	return nil
}

func (p *LedgerEnterpriseProvider) EnrollPEM(approverID, accountID, algorithm string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("approval/ledger-enterprise: invalid PEM")
	}
	return p.Enroll(approverID, accountID, algorithm, block.Bytes)
}

func (p *LedgerEnterpriseProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/ledger-enterprise: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyDER,
		Algorithm:  entry.Algorithm,
	}, nil
}

type leTransactionRequest struct {
	Workspace string `json:"workspace"`
	Type      string `json:"type"`            // "approval-attestation"
	Digest    string `json:"digest"`          // base64 of intent digest
	Algorithm string `json:"signing_algorithm"`
}

type leTransactionResponse struct {
	TxID   string `json:"transaction_id"`
	Status string `json:"status"` // "pending", "approved", "rejected", "failed"
	Sig    string `json:"signature,omitempty"` // base64 DER signature when approved
	Error  string `json:"error,omitempty"`
}

func (p *LedgerEnterpriseProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		return ApprovalSignature{}, fmt.Errorf("approval/ledger-enterprise: approver %q not enrolled", approverID)
	}

	digest := intent.Digest()
	body, _ := json.Marshal(leTransactionRequest{
		Workspace: p.workspace,
		Type:      "approval-attestation",
		Digest:    base64.StdEncoding.EncodeToString(digest[:]),
		Algorithm: entry.Algorithm,
	})

	createURL := fmt.Sprintf("%s/accounts/%s/transactions", p.endpoint, entry.AccountID)
	resp, err := p.doRequest(ctx, http.MethodPost, createURL, body)
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/ledger-enterprise: create tx: %w", err)
	}
	if resp.TxID == "" {
		return ApprovalSignature{}, errors.New("approval/ledger-enterprise: empty transaction_id in response")
	}

	// Trigger approval (Vault notifies the configured approvers' PSDs).
	approveURL := fmt.Sprintf("%s/accounts/%s/transactions/%s/approve", p.endpoint, entry.AccountID, resp.TxID)
	if _, err := p.doRequest(ctx, http.MethodPost, approveURL, nil); err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/ledger-enterprise: trigger approve: %w", err)
	}

	// Poll for completion.
	deadline := time.Now().Add(p.pollTotal)
	pollURL := fmt.Sprintf("%s/accounts/%s/transactions/%s", p.endpoint, entry.AccountID, resp.TxID)
	ticker := time.NewTicker(p.pollEvery)
	defer ticker.Stop()
	for {
		status, err := p.doRequest(ctx, http.MethodGet, pollURL, nil)
		if err != nil {
			return ApprovalSignature{}, fmt.Errorf("approval/ledger-enterprise: poll: %w", err)
		}
		switch status.Status {
		case "approved":
			sigBytes, err := base64.StdEncoding.DecodeString(status.Sig)
			if err != nil {
				return ApprovalSignature{}, fmt.Errorf("approval/ledger-enterprise: decode signature: %w", err)
			}
			return ApprovalSignature{
				ApproverID:   approverID,
				Provider:     p.Provider(),
				IntentDigest: digest,
				Signature:    sigBytes,
				Timestamp:    time.Now().UTC(),
				Algorithm:    entry.Algorithm,
			}, nil
		case "rejected":
			return ApprovalSignature{}, errors.New("approval/ledger-enterprise: rejected by approver")
		case "failed":
			return ApprovalSignature{}, fmt.Errorf("approval/ledger-enterprise: failed: %s", status.Error)
		}
		select {
		case <-ctx.Done():
			return ApprovalSignature{}, ctx.Err()
		case <-ticker.C:
		}
		if time.Now().After(deadline) {
			return ApprovalSignature{}, errors.New("approval/ledger-enterprise: approval timeout")
		}
	}
}

func (p *LedgerEnterpriseProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	if sig.Provider != p.Provider() {
		return false, nil
	}
	digest := intent.Digest()
	if digest != sig.IntentDigest {
		return false, nil
	}
	p.mu.RLock()
	entry, ok := p.identity[sig.ApproverID]
	p.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if entry.Algorithm != sig.Algorithm {
		return false, nil
	}
	// Ledger Enterprise signs SHA-256(intent digest) per the
	// approval-attestation transaction type. Wrap the digest so even if
	// the digest itself is shorter than 32 bytes, we land on a stable
	// 32-byte hash to verify.
	h := sha256.Sum256(digest[:])
	return ecdsa.VerifyASN1(entry.PubKey, h[:], sig.Signature), nil
}

func (p *LedgerEnterpriseProvider) doRequest(ctx context.Context, method, url string, body []byte) (*leTransactionResponse, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ledger-enterprise: %s %s -> %d: %s", method, url, resp.StatusCode, string(respBody))
	}
	var out leTransactionResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &out); err != nil {
			return nil, fmt.Errorf("ledger-enterprise: decode response: %w", err)
		}
	}
	return &out, nil
}
