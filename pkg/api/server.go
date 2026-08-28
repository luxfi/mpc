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
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/wallet"
	"github.com/luxfi/mpc/pkg/webauthn"
)

// MPCBackend is the interface the API layer uses to trigger MPC operations.
// All mutation methods require orgID for tenant-scoped key storage.
//
// TriggerSign takes the network the signature is for. It is not optional and
// there is no curve parameter: a wallet holds a secp256k1 key and an Ed25519
// key at once, so the curve is a property of the request, and the backend
// derives it from the network through the one table in pkg/types. Callers name
// what they are signing for; they never name a curve.
type MPCBackend interface {
	TriggerKeygen(orgID, walletID string) (*KeygenResult, error)
	TriggerSign(orgID, walletID string, network types.NetworkCode, payload []byte) (*SignResult, error)
	TriggerReshare(orgID, walletID string, newThreshold int, newParticipants []string) error
	// TriggerReveal opens a ciphertext the caller brings, under the share set
	// recorded for keyID. The ring answers with shares and stores nothing that
	// needs opening, so the ciphertext is an argument and never a lookup.
	TriggerReveal(orgID, keyID string, ciphertext []byte) ([]byte, error)
	ExportKeyShare(orgID, walletID string) ([]byte, error) // Returns serialized key share for backup encryption
	GetClusterStatus() *ClusterStatus
}

// KeygenResult is the backend response from a keygen operation.
//
// EVMAddress is the canonical 20-byte EVM-runtime account address —
// the format consumed by every EVM-compatible chain. The derivation
// hashes the secp256k1 pubkey with Keccak256 — that's HOW. The value
// IS "EVM-runtime account address" — that's WHAT.
type KeygenResult struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey string `json:"ecdsa_pub_key"`
	EDDSAPubKey string `json:"eddsa_pub_key"`
	EVMAddress  string `json:"evm_address,omitempty"`
	BtcAddress  string `json:"btc_address,omitempty"`
	SolAddress  string `json:"sol_address,omitempty"`

	// Threshold is the number of signers required to use this key, and
	// Participants is the configured party set it was generated across.
	//
	// These are reported so a caller can VERIFY the security property it asked
	// for instead of assuming it. Keygen takes no per-request threshold — the
	// ring's own --threshold governs — so without these fields a client that
	// requests 3-of-5 has no way to learn it actually got something else. That
	// is not hypothetical: luxfi/kms pkg/keys/manager.go validated req.Threshold
	// and then stored `Threshold: result.Threshold`, which was always 0 because
	// mpcd never sent the field. Every validator key set on record reads 0-of-0.
	// Clients must compare these against what they requested and fail closed.
	Threshold    int      `json:"threshold,omitempty"`
	Participants []string `json:"participants,omitempty"`
}

type SignResult struct {
	R string `json:"r,omitempty"`
	S string `json:"s,omitempty"`
	// V is the ECDSA recovery id ("0" or "1") for secp256k1 signatures, empty
	// for schemes without recovery (ed25519/FROST). Signature carries the
	// canonical ecrecover-ready blob r‖s‖v (65 bytes) when recoverable.
	V         string `json:"v,omitempty"`
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
	db              *db.Database
	mpc             MPCBackend
	hsm             HSMProvider // optional: server-side HSM co-signing
	tradeApproval   *custody.TradeApprovalService
	txTracker       *txtracker.Tracker
	jwtSecret       []byte
	oidcIssuers     []string
	webauthnRPID    string
	webauthnOrigins map[string]bool
	// livenessVerifier validates the liveness attestation attached to
	// /v1/mpc/biometric/enroll. Resolved at boot from the configured
	// provider id: a white-label-registered Verifier if present, else the
	// OSS-default Ed25519 envelope verifier built from the configured
	// public key. Nil disables the endpoint (fails closed).
	livenessVerifier   webauthn.Verifier
	livenessProviderID string
	// livenessBindingMode controls the R3-8 envelope→enrollment binding.
	// BindingStrict (default) rejects envelopes that don't carry
	// credentialHash/challengeId. BindingLax logs a warning instead —
	// intended only for the liveness provider extended-envelope rollout window.
	// Configured via MPC_LIVENESS_BINDING=strict|lax (default strict).
	livenessBindingMode webauthn.BindingMode
	router              chi.Router
	replayGuard         *replayGuard

	// approval is the executive-approval registry consumed by /v1/approval/*.
	// Optional — when nil, those endpoints return 503. Wired via SetApproval.
	approval *ApprovalRegistry

	// tieredWallets is the tiered-wallet registry consumed by /v1/wallets/*.
	// Lazily initialized when nil; wired via SetTieredWalletRegistry.
	tieredWallets wallet.Registry

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

	// Liveness attestation verifier. Resolve the active Verifier from the
	// configured provider id:
	//
	//   MPC_LIVENESS_PROVIDER_ID     — provider id; also the registry key a
	//                                  white-label deployment registers under
	//   MPC_LIVENESS_PUBKEY_ED25519  — base64-standard Ed25519 public key for
	//                                  the OSS-default envelope verifier
	//
	// A deployment that registers its own webauthn.Verifier under the
	// provider id (e.g. a regulated broker wiring its own PAD-2 vendor) wins;
	// otherwise, if a public key is configured, the OSS-default Ed25519
	// envelope verifier is used. With neither, livenessVerifier stays nil
	// and /v1/mpc/biometric/enroll refuses every request — an unconfigured
	// verifier MUST NOT fall back to trusting body-supplied scores.
	livenessProviderID := os.Getenv("MPC_LIVENESS_PROVIDER_ID")
	var livenessVerifier webauthn.Verifier
	if v, ok := webauthn.LookupVerifier(livenessProviderID); ok {
		livenessVerifier = v
	} else if raw := os.Getenv("MPC_LIVENESS_PUBKEY_ED25519"); raw != "" {
		if dec, err := base64.StdEncoding.DecodeString(raw); err == nil && len(dec) == ed25519.PublicKeySize {
			livenessVerifier = webauthn.Ed25519EnvelopeVerifier{
				PubKey:     ed25519.PublicKey(dec),
				ProviderID: livenessProviderID,
			}
		}
	}

	// R3-8 binding mode. Default STRICT; ops may toggle to LAX during a
	// vendor's extended-envelope rollout. LAX emits a warn log on every
	// permissive accept so rollout progress is observable.
	bindingMode := webauthn.BindingStrict
	if strings.ToLower(strings.TrimSpace(os.Getenv("MPC_LIVENESS_BINDING"))) == "lax" {
		bindingMode = webauthn.BindingLax
	}

	s := &Server{
		db:                  database,
		mpc:                 mpcBackend,
		txTracker:           tracker,
		jwtSecret:           []byte(jwtSecret),
		oidcIssuers:         oidcIssuers,
		webauthnRPID:        rpID,
		webauthnOrigins:     webauthnOrigins,
		livenessVerifier:    livenessVerifier,
		livenessProviderID:  livenessProviderID,
		livenessBindingMode: bindingMode,
		replayGuard:         newReplayGuard(),
		Events:              NewEventBus(),
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

	// Landing page, and the two assets it names. See landing.go.
	r.Get("/", landing)
	r.Get("/favicon.svg", favicon)
	r.Get("/favicon.ico", ico)
	r.Get("/fonts/Zen-Variable.woff2", zen)

	// Health check (public, outside /v1, for K8s probes)
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

			// ── /v1/mpc/* — MPC spec surface
			// Canonical routes defined in the MPC OpenAPI spec.
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
// and biometric approval flow. When set, the /v1/trade endpoints are active.
func (s *Server) SetTradeApproval(notifier custody.PushNotifier) {
	s.tradeApproval = custody.NewTradeApprovalService(s.db.ORM, notifier)
}

// Handler returns the underlying http.Handler for mounting on external servers (e.g. Hanzo Base).
func (s *Server) Handler() http.Handler {
	return s.router
}
