package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/luxfi/mpc/pkg/db"
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

type Server struct {
	db        *db.Database
	mpc       MPCBackend
	jwtSecret []byte
	router    chi.Router
	server    *http.Server
}

func NewServer(database *db.Database, mpcBackend MPCBackend, jwtSecret string, listenAddr string) *Server {
	s := &Server{
		db:        database,
		mpc:       mpcBackend,
		jwtSecret: []byte(jwtSecret),
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

		// Public payment page
		r.Get("/pay/{token}", s.handlePublicPay)

		// Bridge signing endpoints (API key or JWT auth)
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Post("/generate_mpc_sig", s.handleBridgeSign)
			r.Post("/complete", s.handleBridgeComplete)
		})

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Use(s.auditMiddleware)

			// MFA
			r.Post("/auth/mfa/setup", s.handleMFASetup)
			r.Post("/auth/mfa/verify", s.handleMFAVerify)

			// Users & Teams
			r.Get("/users", s.handleListUsers)
			r.Post("/users", s.handleInviteUser)
			r.Patch("/users/{id}", s.handleUpdateUser)
			r.Delete("/users/{id}", s.handleDeleteUser)

			// API Keys
			r.Get("/api-keys", s.handleListAPIKeys)
			r.Post("/api-keys", s.handleCreateAPIKey)
			r.Delete("/api-keys/{id}", s.handleDeleteAPIKey)

			// Vaults
			r.Get("/vaults", s.handleListVaults)
			r.Post("/vaults", s.handleCreateVault)
			r.Get("/vaults/{id}", s.handleGetVault)
			r.Patch("/vaults/{id}", s.handleUpdateVault)
			r.Delete("/vaults/{id}", s.handleDeleteVault)

			// Wallets
			r.Get("/vaults/{id}/wallets", s.handleListWallets)
			r.Post("/vaults/{id}/wallets", s.handleCreateWallet)
			r.Get("/wallets/{id}", s.handleGetWallet)
			r.Get("/wallets/{id}/addresses", s.handleGetWalletAddresses)
			r.Post("/wallets/{id}/reshare", s.handleReshareWallet)
			r.Get("/wallets/{id}/history", s.handleWalletHistory)

			// Transactions
			r.Post("/transactions", s.handleCreateTransaction)
			r.Get("/transactions", s.handleListTransactions)
			r.Get("/transactions/{id}", s.handleGetTransaction)
			r.Post("/transactions/{id}/approve", s.handleApproveTransaction)
			r.Post("/transactions/{id}/reject", s.handleRejectTransaction)

			// Policies
			r.Get("/policies", s.handleListPolicies)
			r.Post("/policies", s.handleCreatePolicy)
			r.Patch("/policies/{id}", s.handleUpdatePolicy)
			r.Delete("/policies/{id}", s.handleDeletePolicy)

			// Whitelist
			r.Get("/whitelist", s.handleListWhitelist)
			r.Post("/whitelist", s.handleAddWhitelist)
			r.Delete("/whitelist/{id}", s.handleDeleteWhitelist)

			// Webhooks
			r.Get("/webhooks", s.handleListWebhooks)
			r.Post("/webhooks", s.handleCreateWebhook)
			r.Patch("/webhooks/{id}", s.handleUpdateWebhook)
			r.Delete("/webhooks/{id}", s.handleDeleteWebhook)
			r.Post("/webhooks/{id}/test", s.handleTestWebhook)

			// Subscriptions
			r.Get("/subscriptions", s.handleListSubscriptions)
			r.Post("/subscriptions", s.handleCreateSubscription)
			r.Get("/subscriptions/{id}", s.handleGetSubscription)
			r.Patch("/subscriptions/{id}", s.handleUpdateSubscription)
			r.Delete("/subscriptions/{id}", s.handleDeleteSubscription)
			r.Post("/subscriptions/{id}/pay-now", s.handlePayNow)

			// Payment Requests
			r.Post("/payment-requests", s.handleCreatePaymentRequest)
			r.Get("/payment-requests", s.handleListPaymentRequests)
			r.Get("/payment-requests/{id}", s.handleGetPaymentRequest)
			r.Post("/payment-requests/{id}/pay", s.handlePayPaymentRequest)

			// Smart Wallets
			r.Post("/wallets/{id}/smart-wallet", s.handleDeploySmartWallet)
			r.Get("/wallets/{id}/smart-wallets", s.handleListSmartWallets)
			r.Get("/smart-wallets/{id}", s.handleGetSmartWallet)
			r.Post("/smart-wallets/{id}/propose", s.handleProposeSafeTx)
			r.Post("/smart-wallets/{id}/execute", s.handleExecuteSafeTx)
			r.Post("/smart-wallets/{id}/user-operation", s.handleUserOperation)

			// Audit
			r.Get("/audit", s.handleListAudit)

			// Status
			r.Get("/status", s.handleStatus)
			r.Get("/info", s.handleInfo)
		})
	})

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

// Shutdown gracefully drains connections and stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
