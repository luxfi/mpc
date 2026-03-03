package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/txtracker"
)

// MPCBackend is the interface the API layer uses to trigger MPC operations.
type MPCBackend interface {
	TriggerKeygen(walletID string) (*KeygenResult, error)
	TriggerSign(walletID string, payload []byte) (*SignResult, error)
	TriggerReshare(walletID string, newThreshold int, newParticipants []string) error
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
	db          *db.Database
	mpc         MPCBackend
	hsm         HSMProvider // optional: server-side HSM co-signing
	txTracker   *txtracker.Tracker
	jwtSecret   []byte
	oidcIssuers []string
	router      chi.Router
	server      *http.Server
}

func NewServer(database *db.Database, mpcBackend MPCBackend, jwtSecret string, listenAddr string, oidcIssuers ...string) *Server {
	// Default allowed issuers if none provided
	if len(oidcIssuers) == 0 {
		oidcIssuers = []string{
			"https://hanzo.id",
			"https://lux.id",
			"https://pars.id",
			"https://id.zoo.network",
		}
	}

	// Transaction lifecycle tracker (RPC clients added via SetTxTrackerRPC)
	tracker := txtracker.New(txtracker.Config{
		Database: database,
	})

	s := &Server{
		db:          database,
		mpc:         mpcBackend,
		txTracker:   tracker,
		jwtSecret:   []byte(jwtSecret),
		oidcIssuers: oidcIssuers,
	}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(120 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://cloud.lux.network", "https://mpc.lux.network", "https://bridge.lux.network", "http://localhost:3000"},
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
	r.Route("/api/v1", func(r chi.Router) {
		// Auth (no middleware)
		r.Post("/auth/register", s.handleRegister)
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/refresh", s.handleRefresh)
		r.Post("/auth/oidc", s.handleOIDCExchange)

		// Public payment page
		r.Get("/pay/{token}", s.handlePublicPay)

		// Bridge signing endpoints (API key or JWT auth; API key needs "sign" permission)
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Use(requirePermission("sign"))
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

			// Transactions — signers+ can create/approve; viewers can read
			r.Get("/transactions", s.handleListTransactions)
			r.Get("/transactions/{id}", s.handleGetTransaction)
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin", "signer", "api"))
				r.Post("/transactions", s.handleCreateTransaction)
				r.Post("/transactions/{id}/approve", s.handleApproveTransaction)
				r.Post("/transactions/{id}/reject", s.handleRejectTransaction)
			})

			// Policies — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Get("/policies", s.handleListPolicies)
				r.Post("/policies", s.handleCreatePolicy)
				r.Patch("/policies/{id}", s.handleUpdatePolicy)
				r.Delete("/policies/{id}", s.handleDeletePolicy)
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
				r.Use(requireRole("owner", "admin", "signer", "api"))
				r.Post("/subscriptions", s.handleCreateSubscription)
				r.Patch("/subscriptions/{id}", s.handleUpdateSubscription)
				r.Delete("/subscriptions/{id}", s.handleDeleteSubscription)
				r.Post("/subscriptions/{id}/pay-now", s.handlePayNow)
			})

			// Payment Requests — signer+ to create/pay
			r.Get("/payment-requests", s.handleListPaymentRequests)
			r.Get("/payment-requests/{id}", s.handleGetPaymentRequest)
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin", "signer", "api"))
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
				r.Use(requireRole("owner", "admin", "signer", "api"))
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

			// Intents & Settlements — signer+ can create; viewers can read
			r.Get("/intents", s.handleListIntents)
			r.Get("/intents/{id}", s.handleGetIntent)
			r.Get("/settlements", s.handleListSettlements)
			r.Get("/settlements/{id}", s.handleGetSettlement)
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin", "signer", "api"))
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

			// Audit — owner/admin only
			r.Group(func(r chi.Router) {
				r.Use(requireRole("owner", "admin"))
				r.Get("/audit", s.handleListAudit)
			})

			// Status — any authenticated (including API keys)
			r.Get("/status", s.handleStatus)
			r.Get("/info", s.handleInfo)
		})
	})

	// Start background intent expiry reaper
	s.StartIntentReaper(context.Background(), 5*time.Minute)

	s.router = r
	s.server = &http.Server{
		Addr:         listenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening and returns the underlying *http.Server so the caller
// can orchestrate graceful shutdown via srv.Shutdown(ctx). ListenAndServe runs
// in a goroutine; its error (if any) is sent on the returned channel.
func (s *Server) Start() (*http.Server, <-chan error) {
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()
	return s.server, errCh
}

// SetHSM configures the server-side HSM provider for intent co-signing.
// When set, the co-sign endpoint signs with the HSM directly instead of
// accepting client-submitted signatures (prevents forged co-signatures).
func (s *Server) SetHSM(hsm HSMProvider) {
	s.hsm = hsm
}

// Shutdown gracefully drains connections and stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

const landingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lux MPC — Threshold Signing Service</title>
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
<h1>Lux MPC</h1>
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
<a href="/api/v1/bridge/networks">Networks</a>
</div>
<p class="status">v0.3.3 &bull; Post-Quantum TLS 1.3 &bull; ZapDB Encrypted Storage</p>
</div>
</body>
</html>`
