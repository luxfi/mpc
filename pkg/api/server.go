package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/luxfi/mpc/pkg/custody"
	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/txtracker"
	"github.com/luxfi/mpc/pkg/wallet"
	"github.com/luxfi/mpc/pkg/webauthn"
)

// MPCBackend is the interface the API layer uses to trigger MPC operations.
// All mutation methods require orgID for tenant-scoped key storage.
type MPCBackend interface {
	TriggerKeygen(orgID, walletID string) (*KeygenResult, error)
	TriggerSign(orgID, walletID string, payload []byte) (*SignResult, error)
	TriggerReshare(orgID, walletID string, newThreshold int, newParticipants []string) error
	ExportKeyShare(orgID, walletID string) ([]byte, error) // Returns serialized key share for backup encryption
	GetClusterStatus() *ClusterStatus
}

type KeygenResult struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey string `json:"ecdsa_pub_key"`
	EDDSAPubKey string `json:"eddsa_pub_key"`
	EthAddress  string `json:"eth_address"`
	BtcAddress  string `json:"btc_address,omitempty"`
	SolAddress  string `json:"sol_address,omitempty"`
}

type SignResult struct {
	R         string `json:"r,omitempty"`
	S         string `json:"s,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type ClusterStatus struct {
	NodeID         string `json:"node_id"`
	Mode           string `json:"mode"`
	ExpectedPeers  int    `json:"expected_peers"`
	ConnectedPeers int    `json:"connected_peers"`
	Ready          bool   `json:"ready"`
	Threshold      int    `json:"threshold"`
	Version        string `json:"version"`
}

// HSMProvider abstracts hardware security module operations for co-signing.
type HSMProvider interface {
	Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)
	Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error)
}

type Server struct {
	db             *db.Database
	mpc            MPCBackend
	hsm            HSMProvider // optional: server-side HSM co-signing
	tradeApproval  *custody.TradeApprovalService
	txTracker      *txtracker.Tracker
	jwtSecret      []byte
	oidcIssuers    []string
	webauthnRPID   string
	webauthnOrigins map[string]bool
	// PubKey is the Ed25519 verifying key used to validate
	//  (or any other configured PAD-2 liveness provider) attestations
	// attached to /v1/mpc/biometric/enroll. Nil disables the endpoint.
	PubKey     ed25519.PublicKey
	ProviderID string
	// livenessBindingMode controls the R3-8 envelope→enrollment binding.
	// BindingStrict (default) rejects envelopes that don't carry
	// credentialHash/challengeId. BindingLax logs a warning instead —
	// intended only for the  extended-envelope rollout window.
	// Configured via MPC_LIVENESS_BINDING=strict|lax (default strict).
	livenessBindingMode webauthn.BindingMode
	router         chi.Router
	replayGuard    *replayGuard

	// tieredWallets is the registry for the 9-tier wallet architecture
	// (pkg/wallet). Lazily initialized to NewInMemoryRegistry() on first
	// use. Tests / production wrappers can install a custom Registry via
	// SetTieredWalletRegistry.
	tieredWallets wallet.Registry

	// approval holds the pluggable executive-approval registry
	// (pkg/approval). Optional — when nil, /v1/approval/* returns 503.
	// Wire via Server.SetApproval after constructing the providers + the
	// orchestrator binding map.
	approval *ApprovalRegistry

	// Events is the broadcast channel for server-side events (intent status,
	// signing progress, wallet events). Handlers publish here; WebSocket
	// clients and ZAP subscribers receive.
	Events *EventBus
}

// maxBodySize returns middleware that limits request body size to prevent OOM
// from oversized payloads. Handlers that read beyond the limit get an error
// from http.MaxBytesReader.
func maxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

func NewServer(database *db.Database, mpcBackend MPCBackend, jwtSecret string, oidcIssuers ...string) *Server {
	// Default allowed issuers if none provided
	if len(oidcIssuers) == 0 {
		oidcIssuers = []string{
			"https://hanzo.id",
			"https://lux.id",
		}
	}

	// WebAuthn RP ID — configurable via env, default lux.network
	rpID := os.Getenv("MPC_WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "lux.network"
	}

	// WebAuthn allowed origins — configurable via env (comma-separated)
	webauthnOrigins := map[string]bool{}
	if raw := os.Getenv("MPC_WEBAUTHN_ORIGINS"); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				webauthnOrigins[o] = true
			}
		}
	}
	// Default WebAuthn origins — tenants add their own via MPC_WEBAUTHN_ORIGINS env.
	for _, o := range []string{
		"https://lux.network",
		"https://mpc.lux.network",
	} {
		webauthnOrigins[o] = true
	}

	// Transaction lifecycle tracker (RPC clients added via SetTxTrackerRPC)
	tracker := txtracker.New(txtracker.Config{
		Database: database,
	})

	//  liveness attestation verifier. Configure via:
	//
	//   MPC__PUBKEY_ED25519  — base64-standard Ed25519 public key
	//   MPC__PROVIDER_ID     — optional provider id lock (e.g. "")
	//
	// Without the pubkey configured, /v1/mpc/biometric/enroll refuses every
	// request. This is deliberate: an unconfigured verifier MUST NOT fall
	// back to trusting body-supplied liveness scores.
	var sgKey ed25519.PublicKey
	if raw := os.Getenv("MPC__PUBKEY_ED25519"); raw != "" {
		if dec, err := base64.StdEncoding.DecodeString(raw); err == nil && len(dec) == ed25519.PublicKeySize {
			sgKey = ed25519.PublicKey(dec)
		}
	}

	// R3-8 binding mode. Default STRICT; ops may toggle to LAX during
	// the  extended-envelope rollout. LAX emits a warn log on
	// every permissive accept so rollout progress is observable.
	bindingMode := webauthn.BindingStrict
	if strings.ToLower(strings.TrimSpace(os.Getenv("MPC_LIVENESS_BINDING"))) == "lax" {
		bindingMode = webauthn.BindingLax
	}

	s := &Server{
		db:                   database,
		mpc:                  mpcBackend,
		txTracker:            tracker,
		jwtSecret:            []byte(jwtSecret),
		oidcIssuers:          oidcIssuers,
		webauthnRPID:         rpID,
		webauthnOrigins:      webauthnOrigins,
		PubKey:     sgKey,
		ProviderID: os.Getenv("MPC__PROVIDER_ID"),
		livenessBindingMode:  bindingMode,
		replayGuard:          newReplayGuard(),
		Events:               NewEventBus(),
	}

	// CORS origins — Lux infrastructure only. Tenants add via MPC_CORS_ORIGINS env.
	corsOrigins := []string{
		"https://cloud.lux.network",
		"https://mpc.lux.network",
		"https://bridge.lux.network",
		"http://localhost:3000",
	}
	if raw := os.Getenv("MPC_CORS_ORIGINS"); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				corsOrigins = append(corsOrigins, o)
			}
		}
	}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(maxBodySize(1 << 20)) // 1 MB
	r.Use(chimw.Timeout(120 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   corsOrigins,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(RateLimitMiddleware(100))

	// Landing page
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(landingHTML))
	})

	// Health check (public, outside /api/v1, for K8s probes)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Public routes
	r.Route("/v1", func(r chi.Router) {
		// Auth (no middleware)
		r.Post("/auth/register", s.handleRegister)
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/refresh", s.handleRefresh)
		r.Post("/auth/oidc", s.handleOIDCExchange)

		// WebSocket — auth via query param ?token=<jwt> (headers not sent on WS upgrade)
		r.Get("/ws", s.handleWebSocket)

		// Public payment page
		r.Get("/pay/{token}", s.handlePublicPay)

		// Bridge signing endpoints (API key or JWT auth; API key needs "sign" permission)
		// Tighter rate limit for signing: 20 RPM per IP (separate from global 100 RPM).
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Use(requirePermission("sign"))
			r.Use(RateLimitMiddleware(20))
			r.Post("/generate_mpc_sig", s.handleBridgeSign)
			r.Post("/complete", s.handleBridgeComplete)
		})

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Use(s.auditMiddleware)

			// MFA (any authenticated user)
			r.Post("/auth/mfa/setup", s.handleMFASetup)
			r.Post("/auth/mfa/verify", s.handleMFAVerify)

			// Users & Teams — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Get("/users", s.handleListUsers)
				r.Post("/users", s.handleInviteUser)
				r.Patch("/users/{id}", s.handleUpdateUser)
				r.Delete("/users/{id}", s.handleDeleteUser)
			})

			// API Keys — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Get("/api-keys", s.handleListAPIKeys)
				r.Post("/api-keys", s.handleCreateAPIKey)
				r.Delete("/api-keys/{id}", s.handleDeleteAPIKey)
			})

			// Vaults — all authenticated; mutations require admin+
			r.Get("/vaults", s.handleListVaults)
			r.Get("/vaults/{id}", s.handleGetVault)
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Post("/vaults", s.handleCreateVault)
				r.Patch("/vaults/{id}", s.handleUpdateVault)
				r.Delete("/vaults/{id}", s.handleDeleteVault)
			})

			// Wallets — keygen/reshare require admin+; sign requires signer+
			r.Get("/vaults/{id}/wallets", s.handleListWallets)
			r.Get("/wallets/{id}", s.handleGetWallet)
			r.Get("/wallets/{id}/addresses", s.handleGetWalletAddresses)
			r.Get("/wallets/{id}/history", s.handleWalletHistory)
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Post("/vaults/{id}/wallets", s.handleCreateWallet)
				r.Post("/wallets/{id}/reshare", s.handleReshareWallet)
			})

			// Transactions (legacy create/approve/reject plumbing kept as
			// it is the substrate for the unified /v1/mpc/operations view).
			// The read surface for operations is /v1/mpc/operations below;
			// direct POST /v1/transactions retained as internal entry point
			// for intents/payments which wire their own flows.
			r.Group(func(r chi.Router) {
				r.Use(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:transactions:create"))
				r.Post("/transactions", s.handleCreateTransaction)
			})

			// Whitelist — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Get("/whitelist", s.handleListWhitelist)
				r.Post("/whitelist", s.handleAddWhitelist)
				r.Delete("/whitelist/{id}", s.handleDeleteWhitelist)
			})

			// Webhooks — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Get("/webhooks", s.handleListWebhooks)
				r.Post("/webhooks", s.handleCreateWebhook)
				r.Patch("/webhooks/{id}", s.handleUpdateWebhook)
				r.Delete("/webhooks/{id}", s.handleDeleteWebhook)
				r.Post("/webhooks/{id}/test", s.handleTestWebhook)
			})

			// Subscriptions — signer+ to create/pay; viewers can read
			r.Get("/subscriptions", s.handleListSubscriptions)
			r.Get("/subscriptions/{id}", s.handleGetSubscription)
			r.Group(func(r chi.Router) {
				r.Use(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:subscriptions:write"))
				r.Post("/subscriptions", s.handleCreateSubscription)
				r.Patch("/subscriptions/{id}", s.handleUpdateSubscription)
				r.Delete("/subscriptions/{id}", s.handleDeleteSubscription)
				r.Post("/subscriptions/{id}/pay-now", s.handlePayNow)
			})

			// Payment Requests — signer+ to create/pay
			r.Get("/payment-requests", s.handleListPaymentRequests)
			r.Get("/payment-requests/{id}", s.handleGetPaymentRequest)
			r.Group(func(r chi.Router) {
				r.Use(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:payment-requests:write"))
				r.Post("/payment-requests", s.handleCreatePaymentRequest)
				r.Post("/payment-requests/{id}/pay", s.handlePayPaymentRequest)
			})

			// Smart Wallets — admin+ to deploy; signer+ to propose/execute
			r.Get("/wallets/{id}/smart-wallets", s.handleListSmartWallets)
			r.Get("/smart-wallets/{id}", s.handleGetSmartWallet)
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Post("/wallets/{id}/smart-wallet", s.handleDeploySmartWallet)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:smart-wallets:write"))
				r.Post("/smart-wallets/{id}/propose", s.handleProposeSafeTx)
				r.Post("/smart-wallets/{id}/execute", s.handleExecuteSafeTx)
				r.Post("/smart-wallets/{id}/user-operation", s.handleUserOperation)
			})

			// Bridge admin — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Get("/bridge/config", s.handleGetBridgeConfig)
				r.Patch("/bridge/config", s.handleUpdateBridgeConfig)
				r.Get("/bridge/networks", s.handleListBridgeNetworks)
			})

			// WebAuthn/Biometric — any authenticated user can register devices and approve with biometrics
			r.Post("/webauthn/register/begin", s.handleRegisterWebAuthnBegin)
			r.Post("/webauthn/register/complete", s.handleRegisterWebAuthnComplete)
			r.Post("/webauthn/verify", s.handleVerifyWebAuthn) // Biometric approval of transactions
			r.Get("/webauthn/credentials", s.handleListWebAuthnCredentials)
			r.Delete("/webauthn/credentials/{id}", s.handleDeleteWebAuthnCredential)

			// Trade Approval — push notification + biometric signing flow
			// Submit requires signer+ (ATS service account); approve/reject require the trade owner
			r.Get("/trade/pending", s.handlePendingTrades)
			r.Group(func(r chi.Router) {
				r.Use(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:trade:write"))
				r.Post("/trade/submit", s.handleTradeSubmit)
				r.Post("/trade/approve", s.handleTradeApprove)
				r.Post("/trade/reject", s.handleTradeReject)
			})

			// Intents & Settlements — signer+ can create; viewers can read
			r.Get("/intents", s.handleListIntents)
			r.Get("/intents/{id}", s.handleGetIntent)
			r.Get("/settlements", s.handleListSettlements)
			r.Get("/settlements/{id}", s.handleGetSettlement)
			r.Group(func(r chi.Router) {
				r.Use(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:sign"))
				r.Use(RateLimitMiddleware(20)) // signing rate limit: 20 RPM per IP
				r.Post("/intents", s.handleCreateIntent)
				r.Post("/intents/{id}/sign", s.handleSignIntent)
				r.Post("/intents/{id}/co-sign", s.handleCoSignIntent)
			})

			// Wallet Backup — admin+ to create; signer+ to recover
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Post("/wallets/{id}/backup", s.handleCreateWalletBackup)
				r.Get("/wallets/{id}/backup", s.handleGetWalletBackup)
			})

			// Legacy audit route removed — moved to /v1/mpc/audit.

			// Validator key management (KMS) — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				s.registerKMSRoutes(r)
			})

			// Status — any authenticated (including API keys)
			r.Get("/status", s.handleStatus)
			r.Get("/info", s.handleInfo)

			// ── /v1/mpc/* — Liquidity MPC spec surface
			// Canonical routes defined in ~/work/liquidity/openapi/mpc.yaml.
			// No alias paths, no backwards compatibility.
			r.Route("/mpc", func(r chi.Router) {
				// Wallets
				r.Get("/wallets", s.handleMpcListWallets)
				r.Post("/wallets", s.handleMpcCreateWallet)
				r.Get("/wallets/balances", s.handleMpcWalletBalances)
				r.Post("/wallets/sweep", s.handleMpcSweepWallet)
				r.Get("/wallets/{id}", s.handleMpcGetWallet)
				r.Patch("/wallets/{id}/default", s.handleMpcSetDefaultWallet)

				// Default wallet
				r.Get("/wallet", s.handleMpcGetDefaultWallet)
				r.Post("/wallet", s.handleMpcCreateDefaultWallet)

				// Balances + crypto
				r.Get("/balances/{address}", s.handleMpcBalancesByAddress)
				r.Get("/crypto/wallet/{asset}", s.handleMpcCryptoWallet)

				// Signing — R2-3: "api" role must additionally carry the
				// concrete permission; a bare API key with permissions=[] is
				// no longer sufficient.
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:sign"), RateLimitMiddleware(20)).
					Post("/sign", s.handleMpcSignDefault)
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:settlement:sign"), RateLimitMiddleware(20)).
					Post("/settlement/sign", s.handleMpcSignSettlement)

				// WebAuthn (spec-named aliases to the existing handlers)
				r.Post("/webauthn/challenge", s.handleRegisterWebAuthnBegin)
				r.Post("/webauthn/verify", s.handleVerifyWebAuthn)

				// Biometric
				r.Post("/biometric/enroll", s.handleBiometricEnroll)
				r.Get("/biometric/status", s.handleBiometricStatus)

				// Sessions (wallet-scoped)
				r.Route("/wallets/{id}/sessions", func(r chi.Router) {
					r.Get("/", s.handleListWalletSessions)
					r.Post("/", s.handleCreateWalletSession)
					r.Get("/{sessionId}", s.handleGetWalletSession)
					r.Delete("/{sessionId}", s.handleRevokeWalletSession)
				})

				// Operations (unified view over Transaction)
				r.Get("/operations", s.handleListOperations)
				r.Get("/operations/{operationId}", s.handleGetOperation)
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:operations:approve")).
					Post("/operations/{operationId}/approve", s.handleApproveOperation)
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:operations:approve")).
					Post("/operations/{operationId}/reject", s.handleRejectOperation)

				// Policies — owner/admin
				r.Group(func(r chi.Router) {
					r.Use(requireRole("owner", "admin"))
					r.Get("/policies", s.handleListPolicies)
					r.Post("/policies", s.handleCreatePolicy)
					r.Get("/policies/{policyId}", s.handleGetPolicy)
					r.Patch("/policies/{policyId}", s.handleUpdatePolicy)
					r.Delete("/policies/{policyId}", s.handleDeletePolicy)
				})

				// Audit — owner/admin
				r.With(requireRole("owner", "admin")).Get("/audit", s.handleMpcListAudit)

				// Treasury — 3-of-5 org governance surface.
				// wallet CRUD requires owner/admin role OR API key with
				// mpc.treasury.admin permission. Sign requires a treasury
				// signer (principal KeyRef must appear in the signer set).
				r.Route("/treasury", func(r chi.Router) {
					r.Group(func(r chi.Router) {
						r.Use(requireRoleOrAPIPermission(
							[]string{"owner", "admin"}, treasuryAdminPermission))
						r.Post("/wallets", s.handleCreateTreasuryWallet)
						r.Get("/wallets", s.handleListTreasuryWallets)
						r.Get("/wallets/{id}", s.handleGetTreasuryWallet)
						r.Post("/wallets/{id}/rotate-signer", s.handleRotateTreasurySigner)
					})
					r.With(requireRoleOrAPIPermission(
						[]string{"owner", "admin", "signer"}, treasurySignPermission)).
						Post("/sign", s.handleTreasurySign)
				})
			})

			// /v1/wallet/* — 9-tier wallet architecture (pkg/wallet).
			// Distinct from /v1/mpc/wallets (Liquidity MPC spec) and
			// /v1/mpc/treasury (3-of-5 governance). One purpose per surface.
			// Tier-aware sign dispatch + domain-separation enforcement.
			r.Route("/wallet", func(r chi.Router) {
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin"}, "mpc:wallet:tier:write")).
					Post("/", s.handleTieredWalletCreate)
				r.Get("/{id}", s.handleTieredWalletGet)
				r.Get("/tier/{tier}", s.handleTieredWalletListByTier)
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:wallet:tier:sign"), RateLimitMiddleware(20)).
					Post("/{id}/sign", s.handleTieredWalletSign)
				r.Get("/{id}/balance", s.handleTieredWalletBalance)
				r.Get("/{id}/usage", s.handleTieredWalletUsage)
			})

			// /v1/approval/* — executive approval flow (pkg/approval).
			// Approvals are SEPARATE from MPC signing: out-of-band
			// (Ledger Enterprise / WebAuthn / KMS / Safe) attest that an
			// authorized human approved the intent before MPC nodes sign
			// the chain transaction. No /api/ prefix per house style.
			r.Route("/approval", func(r chi.Router) {
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:approval:submit")).
					Post("/intent", s.handleApprovalSubmit)
				r.Get("/intent/{id}/status", s.handleApprovalStatus)
				r.With(requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:approval:cast")).
					Post("/intent/{id}/cast", s.handleApprovalCast)
				r.Get("/intent/{id}/bundle", s.handleApprovalBundle)
			})
		})
	})

	// KMS routes are registered INSIDE the authenticated route group above.
	// See registerKMSRoutes — it applies requireRole("owner", "admin").

	// Start background intent expiry reaper
	s.StartIntentReaper(context.Background(), 5*time.Minute)

	// Start background trade expiry reaper (60s interval — trades expire in 5 min)
	s.StartTradeReaper(context.Background(), 60*time.Second)

	s.router = r

	return s
}

// SetHSM configures the server-side HSM provider for intent co-signing.
// When set, the co-sign endpoint signs with the HSM directly instead of
// accepting client-submitted signatures (prevents forged co-signatures).
func (s *Server) SetHSM(hsm HSMProvider) {
	s.hsm = hsm
}

// SetTradeApproval configures the trade approval service for push notification
// and biometric approval flow. When set, the /api/v1/trade endpoints are active.
func (s *Server) SetTradeApproval(notifier custody.PushNotifier) {
	s.tradeApproval = custody.NewTradeApprovalService(s.db.ORM, notifier)
}

// Handler returns the underlying http.Handler for mounting on external servers (e.g. Hanzo Base).
func (s *Server) Handler() http.Handler {
	return s.router
}

const landingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MPC — Threshold Signing Service</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0a0a;color:#e5e5e5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.c{max-width:720px;padding:3rem 2rem;text-align:center}
h1{font-size:2.5rem;font-weight:700;margin-bottom:.5rem;background:linear-gradient(135deg,#7c3aed,#2563eb);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.tag{color:#a1a1aa;font-size:1.1rem;margin-bottom:2.5rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:2rem 0;text-align:left}
.card{background:#18181b;border:1px solid #27272a;border-radius:12px;padding:1.25rem}
.card h3{font-size:.95rem;margin-bottom:.5rem;color:#a78bfa}
.card p{font-size:.85rem;color:#a1a1aa;line-height:1.5}
.chains{display:flex;flex-wrap:wrap;gap:.5rem;justify-content:center;margin:1.5rem 0}
.chip{background:#1e1b4b;border:1px solid #312e81;color:#c4b5fd;padding:.35rem .75rem;border-radius:999px;font-size:.8rem}
.links{margin-top:2rem;display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}
.links a{color:#818cf8;text-decoration:none;font-size:.9rem;padding:.5rem 1rem;border:1px solid #312e81;border-radius:8px;transition:all .2s}
.links a:hover{background:#1e1b4b;border-color:#4f46e5}
.status{margin-top:2rem;font-size:.8rem;color:#52525b}
</style>
</head>
<body>
<div class="c">
<h1>MPC</h1>
<p class="tag">Threshold Signing Service &bull; 3-of-5 Consensus</p>
<div class="cards">
<div class="card"><h3>CGGMP21</h3><p>5-round threshold ECDSA (secp256k1) for Bitcoin, Ethereum, Lux, XRPL, and all EVM chains.</p></div>
<div class="card"><h3>FROST</h3><p>2-round threshold EdDSA (Ed25519) for Solana, TON. BIP-340 Schnorr for Bitcoin Taproot.</p></div>
<div class="card"><h3>Bridge</h3><p>Cross-chain asset bridge with MPC-signed transactions. Multi-network, policy-driven approvals.</p></div>
</div>
<div class="chains">
<span class="chip">Bitcoin</span><span class="chip">Ethereum</span><span class="chip">Lux</span>
<span class="chip">Solana</span><span class="chip">XRPL</span><span class="chip">TON</span>
<span class="chip">Polygon</span><span class="chip">Arbitrum</span><span class="chip">Base</span><span class="chip">BNB</span>
</div>
<div class="links">
<a href="/healthz">API Status</a>
<a href="/health">Cluster Health</a>
<a href="https://bridge.lux.network">Bridge Dashboard</a>
<a href="/v1/bridge/networks">Networks</a>
</div>
<p class="status">v0.3.3 &bull; Post-Quantum TLS 1.3 &bull; ZapDB Encrypted Storage</p>
</div>
</body>
</html>`
