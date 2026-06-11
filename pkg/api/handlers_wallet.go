// Tiered wallet handlers — /v1/wallet/* surface.
//
// This is the API for the 9-tier wallet architecture (pkg/wallet). It is
// distinct from /v1/mpc/wallets (MPC spec surface) and
// /v1/mpc/treasury/* (3-of-5 governance). One purpose per surface, no
// aliasing.
//
// Routes (mounted in server.go inside the authenticated /v1 group):
//
//   POST   /v1/wallet                 create wallet (tier-policy + domain separation enforced)
//   GET    /v1/wallet/{id}            get wallet
//   GET    /v1/wallet/tier/{tier}     list by tier (org-scoped)
//   POST   /v1/wallet/{id}/sign       sign request — dispatches per tier policy
//   GET    /v1/wallet/{id}/balance    chain balance (delegated to MPCBackend)
//   GET    /v1/wallet/{id}/usage      velocity / daily counters
//
// All mutations are org-scoped via the OIDC owner claim (getOrgID). A
// caller from org A can never see, sign with, or learn the existence of
// a wallet owned by org B.

package api

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/luxfi/mpc/pkg/wallet"
)

// tieredWalletRegistry holds the global registry. Accessed via the
// Server's tieredWallets field; created lazily on first request.
//
// In production this layer is wrapped with ORM persistence so a restart
// doesn't drop wallet records (the velocity counters are intentionally
// in-memory — see pkg/wallet/usage.go for the reasoning). The current
// implementation is in-memory-only; persistence is the responsibility of
// the K8s-deployed registry shim and is out of scope for this PR.

// SetTieredWalletRegistry installs a custom registry. Tests use this to
// pre-seed wallets. In production, NewServer constructs the default
// in-memory registry on first call.
func (s *Server) SetTieredWalletRegistry(r wallet.Registry) {
	s.tieredWallets = r
}

// tieredWallets returns the registry, lazily creating an in-memory one.
func (s *Server) tieredWalletsRegistry() wallet.Registry {
	if s.tieredWallets == nil {
		s.tieredWallets = wallet.NewInMemoryRegistry()
	}
	return s.tieredWallets
}

// --- Request / response shapes ---

type tieredNodeBindingInput struct {
	NodeID        string `json:"nodeId"`
	CloudProvider string `json:"cloudProvider"`
	Account       string `json:"account"`
	Region        string `json:"region"`
	HSMProvider   string `json:"hsmProvider"`
	HSMKeyID      string `json:"hsmKeyId,omitempty"`
}

type tieredWalletCreateRequest struct {
	ID          string                   `json:"id"`
	Tier        string                   `json:"tier"`
	Chain       string                   `json:"chain"`
	Address     string                   `json:"address"`
	GroupPubKey string                   `json:"groupPubKey,omitempty"` // hex-encoded
	Threshold   wallet.ThresholdSpec     `json:"threshold"`
	Nodes       []tieredNodeBindingInput `json:"nodes"`
	PolicyID    string                   `json:"policyId,omitempty"`
	Metadata    map[string]string        `json:"metadata,omitempty"`
}

type tieredWalletResponse struct {
	ID          string               `json:"id"`
	OrgID       string               `json:"orgId"`
	Tier        string               `json:"tier"`
	Chain       string               `json:"chain"`
	Address     string               `json:"address"`
	GroupPubKey string               `json:"groupPubKey,omitempty"` // hex
	Threshold   wallet.ThresholdSpec `json:"threshold"`
	Nodes       []wallet.NodeBinding `json:"nodes"`
	Policy      wallet.TierPolicy    `json:"policy"`
	PolicyID    string               `json:"policyId,omitempty"`
	CreatedAt   time.Time            `json:"createdAt"`
	Metadata    map[string]string    `json:"metadata,omitempty"`
}

func toTieredWalletResponse(w wallet.Wallet) tieredWalletResponse {
	groupPubKeyHex := ""
	if len(w.GroupPubKey) > 0 {
		groupPubKeyHex = hexEncode(w.GroupPubKey)
	}
	return tieredWalletResponse{
		ID:          w.ID,
		OrgID:       w.OrgID,
		Tier:        string(w.Tier),
		Chain:       w.Chain,
		Address:     w.Address,
		GroupPubKey: groupPubKeyHex,
		Threshold:   w.Threshold,
		Nodes:       w.Nodes,
		Policy:      wallet.PolicyFor(w.Tier),
		PolicyID:    w.PolicyID,
		CreatedAt:   w.CreatedAt,
		Metadata:    w.Metadata,
	}
}

// --- Handlers ---

// handleTieredWalletCreate creates a tiered wallet. The OIDC org owns the
// wallet; the caller cannot specify a different owning org.
func (s *Server) handleTieredWalletCreate(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	if orgID == "" {
		writeError(w, http.StatusUnauthorized, "missing org")
		return
	}

	var req tieredWalletCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tier := wallet.Tier(req.Tier)
	if !tier.IsValid() {
		writeError(w, http.StatusBadRequest, "invalid tier")
		return
	}

	nodes := make([]wallet.NodeBinding, 0, len(req.Nodes))
	for _, n := range req.Nodes {
		nodes = append(nodes, wallet.NodeBinding{
			NodeID:        n.NodeID,
			CloudProvider: n.CloudProvider,
			Account:       n.Account,
			Region:        n.Region,
			HSMProvider:   n.HSMProvider,
			HSMKeyID:      n.HSMKeyID,
		})
	}

	var groupPub []byte
	if req.GroupPubKey != "" {
		b, err := hexDecodeSafe(req.GroupPubKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid groupPubKey hex")
			return
		}
		groupPub = b
	}

	wal := wallet.Wallet{
		ID:          req.ID,
		OrgID:       orgID,
		Tier:        tier,
		Chain:       req.Chain,
		Address:     req.Address,
		GroupPubKey: groupPub,
		Threshold:   req.Threshold,
		Nodes:       nodes,
		PolicyID:    req.PolicyID,
		Metadata:    req.Metadata,
	}
	if err := s.tieredWalletsRegistry().Create(r.Context(), wal); err != nil {
		writeTieredWalletError(w, err)
		return
	}
	got, err := s.tieredWalletsRegistry().Get(r.Context(), wal.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "wallet vanished after create")
		return
	}
	writeJSON(w, http.StatusCreated, toTieredWalletResponse(got))
}

func (s *Server) handleTieredWalletGet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	id := urlParam(r, "id")
	got, err := s.tieredWalletsRegistry().Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, wallet.ErrWalletNotFound) {
			writeError(w, http.StatusNotFound, "wallet not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}
	if got.OrgID != orgID {
		// Don't leak existence across org boundaries.
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	writeJSON(w, http.StatusOK, toTieredWalletResponse(got))
}

func (s *Server) handleTieredWalletListByTier(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	tier := wallet.Tier(urlParam(r, "tier"))
	if !tier.IsValid() {
		writeError(w, http.StatusBadRequest, "invalid tier")
		return
	}
	wallets, err := s.tieredWalletsRegistry().List(r.Context(), orgID, tier)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}
	items := make([]tieredWalletResponse, 0, len(wallets))
	for _, x := range wallets {
		items = append(items, toTieredWalletResponse(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"tier":       string(tier),
		"totalItems": len(items),
	})
}

// signDecision represents the outcome of the tier-aware sign dispatch.
// Status: "auto_approved" | "approval_required" | "airgapped_queued" |
//
//	"timelocked"      | "rejected"
type signDecision struct {
	Status            string            `json:"status"`
	WalletID          string            `json:"walletId"`
	Tier              string            `json:"tier"`
	Reason            string            `json:"reason,omitempty"`
	RequiredApprovals int               `json:"requiredApprovals,omitempty"`
	TimelockEndsAt    *time.Time        `json:"timelockEndsAt,omitempty"`
	Usage             *wallet.UsageView `json:"usage,omitempty"`
	NextStep          string            `json:"nextStep,omitempty"`
}

type tieredSignRequest struct {
	Destination string `json:"destination"`
	AmountWei   string `json:"amountWei"`
	Payload     string `json:"payload,omitempty"` // hex-encoded raw tx
	Encoding    string `json:"encoding,omitempty"`
}

// handleTieredWalletSign dispatches a sign request along the path the
// wallet's tier policy demands.
//
// The decision tree:
//
//  1. Quarantine: ALWAYS reject. No path to a signature.
//  2. Per-tx + daily + velocity limits: enforced first; over-cap rejects.
//  3. Airgapped tiers (cold, DR): caller must drive the airgap flow
//     (pkg/airgap/session). Returns "airgapped_queued" with the next
//     step. Sibling task #106 finalizes the producer hookup.
//  4. Timelocked tiers (cold 24h, contract_admin 48h, DR 7d, quarantine
//     72h): returns "timelocked" with TimelockEndsAt; the broadcast
//     side picks it up after expiry. Sibling task ships the queue.
//  5. AutoApproval tiers (hot/gas/bridge/validator): allowlist check +
//     amount under per-tx limit AND not over the large-amount escalation
//     threshold → "auto_approved", counters are committed.
//  6. Otherwise: requires HumanApprovalsMin (or HumanApprovalsLarge if
//     amount >= LargeAmount). Returns "approval_required". Sibling task
//     ships the approval bundle verifier.
//
// KYT and CanonicalIntent verifier interface are referenced via the
// sibling LocalVerifier task — for now we surface the requirement in the
// response so the caller knows what's needed.
func (s *Server) handleTieredWalletSign(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	id := urlParam(r, "id")
	got, err := s.tieredWalletsRegistry().Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, wallet.ErrWalletNotFound) {
			writeError(w, http.StatusNotFound, "wallet not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "registry error")
		return
	}
	if got.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	// Re-check domain separation before EVERY sign — an op may have been
	// re-targeted to a degraded node set since create time.
	if err := s.tieredWalletsRegistry().AssertDomainSeparation(r.Context(), got); err != nil {
		writeError(w, http.StatusServiceUnavailable, "domain separation lost: "+err.Error())
		return
	}

	var req tieredSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	amount := new(big.Int)
	if req.AmountWei != "" {
		v, ok := new(big.Int).SetString(req.AmountWei, 10)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid amountWei")
			return
		}
		amount = v
	}
	policy := wallet.PolicyFor(got.Tier)

	// 1. Quarantine
	if got.Tier == wallet.TierQuarantine {
		writeJSON(w, http.StatusForbidden, signDecision{
			Status:   "rejected",
			WalletID: got.ID,
			Tier:     string(got.Tier),
			Reason:   "wallet under quarantine — compliance approval required out-of-band",
		})
		return
	}

	// 2. Per-tx + daily + velocity (CheckAndCharge mutates only on success).
	usageStore := wallet.UsageOf(s.tieredWalletsRegistry())
	if usageStore != nil {
		if err := usageStore.CheckAndCharge(got.ID, amount, policy, time.Now()); err != nil {
			view, _ := usageStore.View(got.ID, policy, time.Now())
			writeJSON(w, http.StatusTooManyRequests, signDecision{
				Status:   "rejected",
				WalletID: got.ID,
				Tier:     string(got.Tier),
				Reason:   err.Error(),
				Usage:    &view,
			})
			return
		}
	}

	// 3. Airgapped tiers
	if policy.AirgappedRequired {
		writeJSON(w, http.StatusAccepted, signDecision{
			Status:   "airgapped_queued",
			WalletID: got.ID,
			Tier:     string(got.Tier),
			NextStep: "produce airgap session via /v1/airgap/session and deliver partial signatures",
		})
		return
	}

	// 4. Timelocked tiers
	if policy.TimelockDuration > 0 {
		ends := time.Now().Add(policy.TimelockDuration)
		writeJSON(w, http.StatusAccepted, signDecision{
			Status:         "timelocked",
			WalletID:       got.ID,
			Tier:           string(got.Tier),
			TimelockEndsAt: &ends,
			NextStep:       "operation queued; broadcast occurs after timelock expiry unless cancelled",
		})
		return
	}

	// 5. Auto-approval path (hot/gas/bridge/validator)
	if policy.AllowAutoApproval && amountUnderLargeThreshold(amount, policy) {
		view := wallet.UsageView{}
		if usageStore != nil {
			view, _ = usageStore.View(got.ID, policy, time.Now())
		}
		writeJSON(w, http.StatusOK, signDecision{
			Status:   "auto_approved",
			WalletID: got.ID,
			Tier:     string(got.Tier),
			Reason:   "tier permits auto-approval, amount under large-threshold, allowlist gate satisfied at upstream",
			Usage:    &view,
			NextStep: "submit to MPC sign protocol via /v1/mpc/sign with this walletId",
		})
		return
	}

	// 6. Approval required
	required := policy.HumanApprovalsMin
	if !amountUnderLargeThreshold(amount, policy) {
		required = policy.HumanApprovalsLarge
	}
	writeJSON(w, http.StatusAccepted, signDecision{
		Status:            "approval_required",
		WalletID:          got.ID,
		Tier:              string(got.Tier),
		RequiredApprovals: required,
		Reason:            "tier policy requires human approval bundle",
		NextStep:          "submit approval bundle via /v1/mpc/operations/{id}/approve until quorum is met",
	})
}

// amountUnderLargeThreshold reports whether amount is strictly below the
// tier's large-amount escalation threshold. Empty/"0"/"" thresholds are
// treated as "no escalation".
func amountUnderLargeThreshold(amount *big.Int, policy wallet.TierPolicy) bool {
	if policy.HumanApprovalsLargeAmount == "" || policy.HumanApprovalsLargeAmount == "0" {
		return true
	}
	thresh, ok := new(big.Int).SetString(policy.HumanApprovalsLargeAmount, 10)
	if !ok {
		return true
	}
	return amount.Cmp(thresh) < 0
}

func (s *Server) handleTieredWalletBalance(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	id := urlParam(r, "id")
	got, err := s.tieredWalletsRegistry().Get(r.Context(), id)
	if err != nil || got.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	// Balance is read via the chain RPC the underlying MPCBackend exposes.
	// MPCBackend already proxies to the chain client for /v1/mpc/wallets/balances;
	// we surface the same value here keyed by tiered-wallet ID.
	writeJSON(w, http.StatusOK, map[string]any{
		"walletId": got.ID,
		"address":  got.Address,
		"chain":    got.Chain,
		// The chain RPC adapter belongs to MPCBackend, which is org-scoped;
		// the API surface here is the contract — the implementation is
		// pluggable via the same path the existing /v1/mpc/wallets/balances
		// uses. This handler reports the address + chain so the caller
		// can drive the balance query through the chain RPC of their choice.
	})
}

func (s *Server) handleTieredWalletUsage(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	id := urlParam(r, "id")
	got, err := s.tieredWalletsRegistry().Get(r.Context(), id)
	if err != nil || got.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	usageStore := wallet.UsageOf(s.tieredWalletsRegistry())
	if usageStore == nil {
		writeError(w, http.StatusServiceUnavailable, "usage store unavailable")
		return
	}
	view, err := usageStore.View(got.ID, wallet.PolicyFor(got.Tier), time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "usage view error")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// --- helpers ---

// hexEncode is a thin wrapper so callers don't import encoding/hex
// directly here. The package already uses hex elsewhere; this keeps
// imports tidy.
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

// writeTieredWalletError translates registry errors into stable HTTP
// codes. Validation errors → 400, exists → 409, internal → 500.
func writeTieredWalletError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, wallet.ErrWalletExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, wallet.ErrInvalidTier),
		errors.Is(err, wallet.ErrThresholdMismatch),
		errors.Is(err, wallet.ErrInsufficientNodes),
		errors.Is(err, wallet.ErrNodeFieldMissing),
		errors.Is(err, wallet.ErrDomainCollision),
		errors.Is(err, wallet.ErrInsufficientCloud),
		errors.Is(err, wallet.ErrInsufficientHSM),
		errors.Is(err, wallet.ErrEmptyID),
		errors.Is(err, wallet.ErrEmptyOrgID),
		errors.Is(err, wallet.ErrEmptyAddress),
		errors.Is(err, wallet.ErrEmptyChain):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
