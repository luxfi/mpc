package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
)

// ChainalysisProvider screens addresses against the Chainalysis KYT API.
//
// The API: https://docs.chainalysis.com/kyt/api/v2.html — we hit the
// "/api/kyt/v2/users/{userId}/withdrawal-attempts" path with GET to
// classify an address. Real usage requires an API key and per-org
// config; here we ship the HTTP client + parser. Network failures
// surface as errors (FAIL CLOSED at the verifier).
type ChainalysisProvider struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewChainalysisProvider constructs a ChainalysisProvider. Endpoint
// defaults to the production KYT base if empty.
func NewChainalysisProvider(endpoint, apiKey string) *ChainalysisProvider {
	if endpoint == "" {
		endpoint = "https://api.chainalysis.com"
	}
	return &ChainalysisProvider{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// chainalysisResponse mirrors the fields we actually use from the
// Chainalysis KYT v2 response. We avoid binding to the full schema so
// the struct stays small and forward-compatible.
type chainalysisResponse struct {
	RiskScore string `json:"risk"`           // "Low", "Medium", "High", "Severe"
	Category  string `json:"riskCategory"`   // category label
	Asset     string `json:"asset"`
	Address   string `json:"address"`
	ExposureUsd float64 `json:"exposureUsd"`
}

// ScreenAddress queries Chainalysis for a single address.
func (c *ChainalysisProvider) ScreenAddress(ctx context.Context, chain, address string) (Verdict, error) {
	if c.apiKey == "" {
		return Verdict{}, errors.New("chainalysis: api key not configured")
	}
	// Build URL: /api/risk/v2/entities/{address}
	u := fmt.Sprintf("%s/api/risk/v2/entities/%s", c.endpoint, url.PathEscape(address))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Token", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("chainalysis: request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return Verdict{}, fmt.Errorf("chainalysis: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("chainalysis: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var parsed chainalysisResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Verdict{}, fmt.Errorf("chainalysis: parse: %w", err)
	}

	// Map Chainalysis risk levels to a numeric score and an approve flag.
	// "Low" approves; everything else rejects. Tunable per-tier in policy.
	score, approved, reason := mapChainalysisRisk(parsed.RiskScore, parsed.Category)
	return Verdict{
		Approved:   approved,
		Reason:     reason,
		RiskScore:  score,
		EvidenceID: parsed.Address,
		Provider:   "chainalysis",
		Timestamp:  time.Now().UTC(),
	}, nil
}

// ScreenTransaction screens the destination address. Chainalysis KYT also
// exposes per-transaction calls; we use the address screen here for
// simplicity and rely on the transaction simulation hash being part of
// the intent body for non-repudiation.
func (c *ChainalysisProvider) ScreenTransaction(ctx context.Context, ci *intent.CanonicalIntent) (Verdict, error) {
	return c.ScreenAddress(ctx, ci.Chain, ci.To)
}

// mapChainalysisRisk maps the Chainalysis textual risk to a score
// and a binary approve decision.
func mapChainalysisRisk(level, category string) (score float64, approved bool, reason string) {
	switch strings.ToLower(level) {
	case "low":
		return 0.1, true, ""
	case "medium":
		return 0.4, false, "chainalysis risk=Medium category=" + category
	case "high":
		return 0.8, false, "chainalysis risk=High category=" + category
	case "severe":
		return 1.0, false, "chainalysis risk=Severe category=" + category
	default:
		return 1.0, false, "chainalysis risk=" + level + " (unknown level treated as severe) category=" + category
	}
}

// =============================================================================
// Stubs for TRM Labs and Elliptic — same interface, document the API
// surface so a follow-on PR can drop in the implementations.
// =============================================================================

// TRMProvider is a stub for TRM Labs Wallet Screening. The real API:
// POST /public/v2/screening/addresses with JSON body
// {"address": "...", "chain": "..."}.
type TRMProvider struct {
	endpoint string
	apiKey   string
}

func NewTRMProvider(endpoint, apiKey string) *TRMProvider {
	return &TRMProvider{endpoint: endpoint, apiKey: apiKey}
}

func (t *TRMProvider) ScreenAddress(_ context.Context, _, _ string) (Verdict, error) {
	return Verdict{}, ErrNotImplemented
}

func (t *TRMProvider) ScreenTransaction(_ context.Context, _ *intent.CanonicalIntent) (Verdict, error) {
	return Verdict{}, ErrNotImplemented
}

// EllipticProvider is a stub for Elliptic Navigator. The real API:
// POST /v2/wallet/synchronous with JSON body
// {"subject":{"asset":"...","hash":"..."}, "type":"wallet_address"}.
type EllipticProvider struct {
	endpoint string
	apiKey   string
	apiSec   string
}

func NewEllipticProvider(endpoint, apiKey, apiSec string) *EllipticProvider {
	return &EllipticProvider{endpoint: endpoint, apiKey: apiKey, apiSec: apiSec}
}

func (e *EllipticProvider) ScreenAddress(_ context.Context, _, _ string) (Verdict, error) {
	return Verdict{}, ErrNotImplemented
}

func (e *EllipticProvider) ScreenTransaction(_ context.Context, _ *intent.CanonicalIntent) (Verdict, error) {
	return Verdict{}, ErrNotImplemented
}
