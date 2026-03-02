package main

import (
	"context"
	"crypto/ed25519"
	crypto_elliptic "crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/hashicorp/consul/api"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	mpcapi "github.com/luxfi/mpc/pkg/api"
	"github.com/luxfi/mpc/pkg/backup"
	"github.com/luxfi/mpc/pkg/config"
	"github.com/luxfi/mpc/pkg/constant"
	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/eventconsumer"
	"github.com/luxfi/mpc/pkg/hsm"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/infra"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/luxfi/mpc/pkg/transport"
	"github.com/luxfi/mpc/pkg/types"
)

const (
	Version                    = "0.3.3"
	DefaultBackupPeriodSeconds = 300 // (5 minutes)
)

func main() {
	app := &cli.Command{
		Name:    "mpcd",
		Usage:   "MPC daemon for threshold signatures (consensus-embedded)",
		Version: Version,
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start a Lux MPC node",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Node name",
						Required: false, // Not required in consensus mode
					},
					&cli.StringFlag{
						Name:    "mode",
						Aliases: []string{"m"},
						Usage:   "Transport mode: 'legacy' (NATS/Consul) or 'consensus' (ZAP/PoA)",
						Value:   "legacy",
					},
					// Consensus mode flags
					&cli.StringFlag{
						Name:  "node-id",
						Usage: "Node ID (consensus mode)",
					},
					&cli.StringFlag{
						Name:  "listen",
						Usage: "P2P listen address (consensus mode)",
						Value: ":9651",
					},
					&cli.StringFlag{
						Name:  "api",
						Usage: "API listen address (consensus mode)",
						Value: ":9800",
					},
					&cli.StringFlag{
						Name:  "data",
						Usage: "Data directory (consensus mode)",
					},
					&cli.StringFlag{
						Name:  "keys",
						Usage: "Keys directory (consensus mode)",
					},
					&cli.IntFlag{
						Name:    "threshold",
						Aliases: []string{"t"},
						Usage:   "Signing threshold",
						Value:   2,
					},
					&cli.StringSliceFlag{
						Name:  "peer",
						Usage: "Peer address (can be specified multiple times)",
					},
					&cli.StringFlag{
						Name:  "log-level",
						Usage: "Log level (debug, info, warn, error)",
						Value: "info",
					},
					// Dashboard API flags
					&cli.StringFlag{
						Name:  "api-db",
						Usage: "PostgreSQL connection URL for dashboard API",
					},
					&cli.StringFlag{
						Name:  "api-kv",
						Usage: "Valkey/Redis address for KV cache (e.g. localhost:6379)",
					},
					&cli.StringFlag{
						Name:  "api-listen",
						Usage: "Dashboard API listen address",
						Value: ":8081",
					},
					&cli.StringFlag{
						Name:  "jwt-secret",
						Usage: "JWT signing secret for dashboard auth",
					},
					// HSM / password provider flags
					&cli.StringFlag{
						Name:    "hsm-provider",
						Usage:   "Password provider type: aws|gcp|azure|env|file (default: env)",
						Sources: cli.EnvVars("MPC_HSM_PROVIDER"),
						Value:   "env",
					},
					&cli.StringFlag{
						Name:    "hsm-key-id",
						Usage:   "HSM key ARN/name/path for ZapDB password decryption",
						Sources: cli.EnvVars("MPC_HSM_KEY_ID"),
					},
					// Legacy mode flags
					&cli.BoolFlag{
						Name:    "decrypt-private-key",
						Aliases: []string{"d"},
						Value:   false,
						Usage:   "Decrypt node private key (legacy mode)",
					},
					&cli.BoolFlag{
						Name:    "prompt-credentials",
						Aliases: []string{"p"},
						Usage:   "Prompt for sensitive parameters (legacy mode)",
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Enable debug logging",
						Value: false,
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					mode := c.String("mode")
					if mode == "consensus" {
						return runNodeConsensus(ctx, c)
					}
					return runNode(ctx, c)
				},
			},
			{
				Name:  "api",
				Usage: "Start Dashboard API server only (no MPC transport)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "db",
						Usage:   "PostgreSQL connection URL",
						Sources: cli.EnvVars("DATABASE_URL", "MPC_API_DB"),
					},
					&cli.StringFlag{
						Name:  "listen",
						Usage: "API listen address",
						Value: ":8081",
					},
					&cli.StringFlag{
						Name:    "jwt-secret",
						Usage:   "JWT signing secret",
						Sources: cli.EnvVars("JWT_SECRET", "MPC_JWT_SECRET"),
					},
					&cli.StringFlag{
						Name:    "cluster-url",
						Usage:   "MPC cluster URL for forwarding operations (e.g. http://mpc-node:9800)",
						Sources: cli.EnvVars("MPC_CLUSTER_URL"),
					},
					&cli.StringFlag{
						Name:    "cluster-api-key",
						Usage:   "API key for authenticating with MPC cluster",
						Sources: cli.EnvVars("MPC_CLUSTER_API_KEY"),
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Enable debug logging",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return runAPIOnly(ctx, c)
				},
			},
			{
				Name:  "version",
				Usage: "Display detailed version information",
				Action: func(ctx context.Context, c *cli.Command) error {
					fmt.Printf("mpcd version %s\n", Version)
					return nil
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runNode(ctx context.Context, c *cli.Command) error {
	nodeName := c.String("name")
	decryptPrivateKey := c.Bool("decrypt-private-key")
	usePrompts := c.Bool("prompt-credentials")
	debug := c.Bool("debug")

	viper.SetDefault("backup_enabled", true)
	config.InitViperConfig()
	environment := viper.GetString("environment")
	logger.Init(environment, debug)

	// Create environment-prefixed node ID
	nodeID := fmt.Sprintf("lux-%s-%s", environment, nodeName)
	logger.Info("Starting MPC node", "nodeID", nodeID, "environment", environment)

	// Handle configuration based on prompt flag
	if usePrompts {
		promptForSensitiveCredentials()
	} else {
		// Validate the config values
		checkRequiredConfigValues()
	}

	consulClient := infra.GetConsulClient(environment)
	keyinfoStore := keyinfo.NewStore(consulClient.KV())
	peers := LoadPeersFromConsul(consulClient)
	// Use the environment-prefixed nodeID we created above
	// nodeID is already set with environment prefix

	zapKV := NewZapKV(nodeName, nodeID)
	defer zapKV.Close()

	// Wrap ZapDB store with KMS-enabled store if configured
	var kvStore kvstore.KVStore = zapKV
	kmsEnabledStore, err := mpc.NewKMSEnabledKVStore(zapKV, nodeID)
	if err != nil {
		logger.Warn("Failed to create KMS-enabled store, using regular ZapDB", "error", err)
	} else {
		kvStore = kmsEnabledStore
		logger.Info("Using KMS-enabled storage for sensitive keys")
	}

	// Start background backup job
	backupEnabled := viper.GetBool("backup_enabled")
	if backupEnabled {
		backupPeriodSeconds := viper.GetInt("backup_period_seconds")
		stopBackup := StartPeriodicBackup(ctx, zapKV, backupPeriodSeconds)
		defer stopBackup()
	}

	identityStore, err := identity.NewFileStore("identity", nodeName, decryptPrivateKey)
	if err != nil {
		logger.Fatal("Failed to create identity store", err)
	}

	natsConn, err := GetNATSConnection(environment)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Close()

	pubsub := messaging.NewNATSPubSub(natsConn)
	keygenBroker, err := messaging.NewJetStreamBroker(ctx, natsConn, event.KeygenBrokerStream, []string{
		event.KeygenRequestTopic,
	})
	if err != nil {
		logger.Fatal("Failed to create keygen jetstream broker", err)
	}
	signingBroker, err := messaging.NewJetStreamBroker(ctx, natsConn, event.SigningPublisherStream, []string{
		event.SigningRequestTopic,
	})
	if err != nil {
		logger.Fatal("Failed to create signing jetstream broker", err)
	}

	_ = messaging.NewNatsDirectMessaging(natsConn) // directMessaging available for future use
	mqManager := messaging.NewNATsMessageQueueManager("mpc", []string{
		"mpc.mpc_keygen_result.*",
		event.SigningResultTopic,
		"mpc.mpc_reshare_result.*",
	}, natsConn)

	genKeyResultQueue := mqManager.NewMessageQueue("mpc_keygen_result")
	defer genKeyResultQueue.Close()
	singingResultQueue := mqManager.NewMessageQueue("mpc_signing_result")
	defer singingResultQueue.Close()
	reshareResultQueue := mqManager.NewMessageQueue("mpc_reshare_result")
	defer reshareResultQueue.Close()

	logger.Info("Node is running", "peerID", nodeID, "name", nodeName)

	peerNodeIDs := GetPeerIDs(peers)
	peerRegistry := mpc.NewRegistry(nodeID, peerNodeIDs, consulClient.KV())

	mpcNode := mpc.NewNode(
		nodeID,
		peerNodeIDs,
		pubsub,
		kvStore,
		keyinfoStore,
		peerRegistry,
		identityStore,
	)

	eventConsumer := eventconsumer.NewEventConsumer(
		mpcNode,
		pubsub,
		genKeyResultQueue,
		singingResultQueue,
		reshareResultQueue,
		identityStore,
	)
	eventConsumer.Run()
	defer eventConsumer.Close()

	timeoutConsumer := eventconsumer.NewTimeOutConsumer(
		natsConn,
		singingResultQueue,
	)

	timeoutConsumer.Run()
	defer timeoutConsumer.Close()
	keygenConsumer := eventconsumer.NewKeygenConsumer(natsConn, keygenBroker, pubsub, peerRegistry)
	signingConsumer := eventconsumer.NewSigningConsumer(natsConn, signingBroker, pubsub, peerRegistry)

	// Make the node ready before starting the signing consumer
	if err := peerRegistry.Ready(); err != nil {
		logger.Error("Failed to mark peer registry as ready", err)
	}
	logger.Info("[READY] Node is ready", "nodeID", nodeID)
	appContext, cancel := context.WithCancel(context.Background())
	// Setup signal handling to cancel context on termination signals.
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		logger.Warn("Shutdown signal received, canceling context...")
		cancel()

		// Gracefully close consumers
		if err := keygenConsumer.Close(); err != nil {
			logger.Error("Failed to close keygen consumer", err)
		}
		if err := signingConsumer.Close(); err != nil {
			logger.Error("Failed to close signing consumer", err)
		}
	}()

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := keygenConsumer.Run(appContext); err != nil {
			logger.Error("error running keygen consumer", err)
			errChan <- fmt.Errorf("keygen consumer error: %w", err)
			return
		}
		logger.Info("Keygen consumer finished successfully")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := signingConsumer.Run(appContext); err != nil {
			logger.Error("error running signing consumer", err)
			errChan <- fmt.Errorf("signing consumer error: %w", err)
			return
		}
		logger.Info("Signing consumer finished successfully")
	}()

	go func() {
		wg.Wait()
		logger.Info("All consumers have finished")
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			logger.Error("Consumer error received", err)
			cancel()
			return err
		}
	}
	return nil
}

// Prompt user for sensitive configuration values
func promptForSensitiveCredentials() {
	fmt.Println("WARNING: Please back up your ZapDB password in a secure location.")
	fmt.Println("If you lose this password, you will permanently lose access to your data!")

	// Prompt for ZapDB password with confirmation
	var badgerPass []byte
	var confirmPass []byte
	var err error

	for {
		fmt.Print("Enter ZapDB password: ")
		badgerPass, err = term.ReadPassword(syscall.Stdin)
		if err != nil {
			logger.Fatal("Failed to read ZapDB password", err)
		}
		fmt.Println() // Add newline after password input

		if len(badgerPass) == 0 {
			fmt.Println("Password cannot be empty. Please try again.")
			continue
		}

		fmt.Print("Confirm ZapDB password: ")
		confirmPass, err = term.ReadPassword(syscall.Stdin)
		if err != nil {
			logger.Fatal("Failed to read confirmation password", err)
		}
		fmt.Println() // Add newline after password input

		if string(badgerPass) != string(confirmPass) {
			fmt.Println("Passwords do not match. Please try again.")
			continue
		}

		break
	}

	// Show masked password for confirmation
	maskedPassword := maskString(string(badgerPass))
	fmt.Printf("Password set: %s\n", maskedPassword)

	viper.Set("zapdb_password", string(badgerPass))

	// Prompt for initiator public key (using regular input since it's not as sensitive)
	var initiatorKey string
	fmt.Print("Enter event initiator public key (hex): ")
	if _, err := fmt.Scanln(&initiatorKey); err != nil {
		logger.Fatal("Failed to read initiator key", err)
	}

	if initiatorKey == "" {
		logger.Fatal("Initiator public key cannot be empty", nil)
	}

	// Show masked key for confirmation
	maskedKey := maskString(initiatorKey)
	fmt.Printf("Event initiator public key set: %s\n", maskedKey)

	viper.Set("event_initiator_pubkey", initiatorKey)
	fmt.Println("\n✓ Configuration complete!")
}

// maskString shows the first and last character of a string, replacing the middle with asterisks
func maskString(s string) string {
	if len(s) <= 2 {
		return s // Too short to mask
	}

	masked := s[0:1]
	for i := 0; i < len(s)-2; i++ {
		masked += "*"
	}
	masked += s[len(s)-1:]

	return masked
}

// Check required configuration values are present
func checkRequiredConfigValues() {
	// Show warning if we're using file-based config but no password is set
	if viper.GetString("zapdb_password") == "" {
		logger.Fatal("ZapDB password is required", nil)
	}

	if viper.GetString("event_initiator_pubkey") == "" {
		logger.Fatal("Event initiator public key is required", nil)
	}
}

func NewConsulClient(addr string) *api.Client {
	// Create a new Consul client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = addr
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		logger.Fatal("Failed to create consul client", err)
	}
	logger.Info("Connected to consul!")
	return consulClient
}

func LoadPeersFromConsul(consulClient *api.Client) []config.Peer { // Create a Consul Key-Value store client
	kv := consulClient.KV()
	peers, err := config.LoadPeersFromConsul(kv, "mpc_peers/")
	if err != nil {
		logger.Fatal("Failed to load peers from Consul", err)
	}
	logger.Info("Loaded peers from consul", "peers", peers)

	return peers
}

func GetPeerIDs(peers []config.Peer) []string {
	var peersIDs []string
	for _, peer := range peers {
		peersIDs = append(peersIDs, peer.ID)
	}
	return peersIDs
}

// Given node name, loop through peers and find the matching ID
func GetIDFromName(name string, peers []config.Peer) string {
	// Get nodeID from node name
	nodeID := config.GetNodeID(name, peers)
	if nodeID == "" {
		logger.Fatal("Empty Node ID", fmt.Errorf("node ID not found for name %s", name))
	}

	return nodeID
}

func NewZapKV(nodeName, nodeID string) *kvstore.Store {
	// ZapDB KV store
	// Use configured db_path or default to current directory + "db"
	basePath := viper.GetString("db_path")
	if basePath == "" {
		basePath = filepath.Join(".", "db")
	}
	dbPath := filepath.Join(basePath, nodeName)

	// Use configured backup_dir or default to current directory + "backups"
	backupDir := viper.GetString("backup_dir")
	if backupDir == "" {
		backupDir = filepath.Join(".", "backups")
	}

	// Create ZapDB config
	config := kvstore.Config{
		NodeID:    nodeName,
		Key:       []byte(viper.GetString("zapdb_password")),
		BackupKey: []byte(viper.GetString("zapdb_password")), // Using same key for backup encryption
		Dir:       backupDir,
		Path:      dbPath,
	}

	kv, err := kvstore.New(config)
	if err != nil {
		logger.Fatal("Failed to create zapdb store", err)
	}
	logger.Info("Connected to zapdb store", "path", dbPath, "backup_dir", backupDir)
	return kv
}

func StartPeriodicBackup(ctx context.Context, zapKV *kvstore.Store, periodSeconds int) func() {
	if periodSeconds <= 0 {
		periodSeconds = DefaultBackupPeriodSeconds
	}
	backupTicker := time.NewTicker(time.Duration(periodSeconds) * time.Second)
	backupCtx, backupCancel := context.WithCancel(ctx)
	go func() {
		for {
			select {
			case <-backupCtx.Done():
				logger.Info("Backup background job stopped")
				return
			case <-backupTicker.C:
				logger.Info("Running periodic ZapDB backup...")
				err := zapKV.Backup()
				if err != nil {
					logger.Error("Periodic ZapDB backup failed", err)
				} else {
					logger.Info("Periodic ZapDB backup completed successfully")
				}
			}
		}
	}()
	return backupCancel
}

func GetNATSConnection(environment string) (*nats.Conn, error) {
	url := viper.GetString("nats.url")
	opts := []nats.Option{
		nats.MaxReconnects(-1), // retry forever
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectHandler(func(nc *nats.Conn) {
			logger.Warn("Disconnected from NATS")
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("Reconnected to NATS", "url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			logger.Info("NATS connection closed!")
		}),
	}

	if environment == constant.EnvProduction {
		clientCert := filepath.Join(".", "certs", "client-cert.pem")
		clientKey := filepath.Join(".", "certs", "client-key.pem")
		caCert := filepath.Join(".", "certs", "rootCA.pem")

		opts = append(opts,
			nats.ClientCert(clientCert, clientKey),
			nats.RootCAs(caCert),
			nats.UserInfo(viper.GetString("nats.username"), viper.GetString("nats.password")),
		)
	}

	return nats.Connect(url, opts...)
}

// runNodeConsensus runs the MPC node with consensus-embedded transport (no NATS/Consul)
func runNodeConsensus(ctx context.Context, c *cli.Command) error {
	nodeID := c.String("node-id")
	listenAddr := c.String("listen")
	dataDir := c.String("data")
	keysDir := c.String("keys")
	threshold := c.Int("threshold")
	peers := c.StringSlice("peer")
	logLevel := c.String("log-level")
	debug := c.Bool("debug")

	if nodeID == "" {
		return fmt.Errorf("--node-id is required in consensus mode")
	}
	if dataDir == "" {
		return fmt.Errorf("--data is required in consensus mode")
	}

	// Initialize logger
	logger.Init("consensus", debug || logLevel == "debug")
	logger.Info("Starting MPC node in consensus mode",
		"nodeID", nodeID,
		"listen", listenAddr,
		"dataDir", dataDir,
		"threshold", threshold,
		"peers", len(peers),
	)

	// Ensure directories exist
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	if keysDir == "" {
		keysDir = filepath.Join(dataDir, "keys")
	}
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Load or generate identity
	privKey, pubKey, err := loadOrGenerateIdentity(keysDir, nodeID)
	if err != nil {
		return fmt.Errorf("failed to load/generate identity: %w", err)
	}

	// Create consensus identity store for verifying messages
	consensusIdentity := NewConsensusIdentityStore(nodeID, privKey, pubKey)

	// Build peer map
	peerMap := make(map[string]string)
	peerMap[nodeID] = listenAddr
	for i, peer := range peers {
		// Parse peer address - format: "nodeID@host:port" or just "host:port"
		parts := strings.SplitN(peer, "@", 2)
		if len(parts) == 2 {
			peerMap[parts[0]] = parts[1]
		} else {
			peerMap[fmt.Sprintf("peer-%d", i)] = peer
		}
	}

	// Get ZapDB password via HSM provider (supports AWS KMS, GCP Cloud KMS, Azure Key Vault, env, file)
	hsmProviderType := c.String("hsm-provider")
	hsmKeyID := c.String("hsm-key-id")

	provider, err := hsm.NewPasswordProvider(hsmProviderType, nil)
	if err != nil {
		return fmt.Errorf("failed to create HSM password provider (%s): %w", hsmProviderType, err)
	}

	zapDBPassword, err := provider.GetPassword(ctx, hsmKeyID)
	if err != nil {
		// Fall back to viper config for backward compatibility
		zapDBPassword = viper.GetString("zapdb_password")
		if zapDBPassword == "" {
			logger.Warn("No ZapDB password set via HSM provider or config, using default (NOT for production!)",
				"provider", hsmProviderType, "error", err)
			zapDBPassword = "dev-password-change-me"
		} else {
			logger.Info("ZapDB password loaded from config file (consider using HSM provider for production)")
		}
	} else {
		logger.Info("ZapDB password loaded via HSM provider", "provider", hsmProviderType)
	}

	// Create transport factory (uses ZapDB for embedded key-share storage)
	factoryCfg := transport.FactoryConfig{
		NodeID:        nodeID,
		ListenAddr:    listenAddr,
		Peers:         peerMap,
		PrivateKey:    privKey,
		PublicKey:     pubKey,
		ZapDBPath:     filepath.Join(dataDir, "db"),
		ZapDBPassword: zapDBPassword,
		BackupDir:     filepath.Join(dataDir, "backups"),
	}

	factory, err := transport.NewFactory(factoryCfg)
	if err != nil {
		return fmt.Errorf("failed to create transport factory: %w", err)
	}

	// Start transport
	if err := factory.Start(ctx); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}
	defer factory.Stop()

	// Create MPC node with consensus transport
	peerIDs := make([]string, 0, len(peerMap)-1)
	for id := range peerMap {
		if id != nodeID {
			peerIDs = append(peerIDs, id)
		}
	}

	// Create PubSub adapter for messaging
	pubSub := NewConsensusPubSubAdapter(factory.PubSub())

	// Create message queue adapters
	genKeyResultQueue := NewConsensusMessageQueue(factory.Transport(), nodeID, "keygen")
	signingResultQueue := NewConsensusMessageQueue(factory.Transport(), nodeID, "signing")
	reshareResultQueue := NewConsensusMessageQueue(factory.Transport(), nodeID, "reshare")

	logger.Info("Node is running in consensus mode", "nodeID", nodeID)

	// Create peer registry using consensus membership
	peerRegistry := NewConsensusPeerRegistry(factory.Registry(), nodeID, peerIDs)

	// Create MPC node
	mpcNode := mpc.NewNode(
		nodeID,
		peerIDs,
		pubSub,
		factory.KVStore(),
		NewConsensusKeyInfoStore(factory.KeyInfoStore(), peerRegistry),
		peerRegistry,
		consensusIdentity,
	)

	// Create event consumer
	eventConsumer := eventconsumer.NewEventConsumer(
		mpcNode,
		pubSub,
		genKeyResultQueue,
		signingResultQueue,
		reshareResultQueue,
		consensusIdentity,
	)
	eventConsumer.Run()
	defer eventConsumer.Close()

	// Mark as ready
	if err := peerRegistry.Ready(); err != nil {
		logger.Error("Failed to mark peer registry as ready", err)
	}
	logger.Info("[READY] Node is ready (consensus mode)", "nodeID", nodeID)

	// Start HTTP API server
	apiAddr := c.String("api")
	if apiAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			ready := peerRegistry.ArePeersReady()
			connected := factory.Transport().GetPeers()
			status := "healthy"
			httpCode := http.StatusOK
			if !ready {
				status = "degraded"
				httpCode = http.StatusServiceUnavailable
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(httpCode)
			resp := map[string]interface{}{
				"status":         status,
				"nodeID":         nodeID,
				"mode":           "consensus",
				"expectedPeers":  len(peerIDs),
				"connectedPeers": connected,
				"ready":          ready,
				"threshold":      threshold,
				"version":        Version,
			}
			json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
			keys, err := factory.KeyInfoStore().ListKeys()
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(keys)
		})
		mux.HandleFunc("/backup", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if zapKV, ok := factory.KVStore().(*kvstore.Store); ok && zapKV.Exec != nil {
				s3Cfg := backup.S3ConfigFromEnv(nodeID)
				mgr, err := backup.NewManager(zapKV.Exec, filepath.Join(dataDir, "backups"), nodeID, 0, s3Cfg)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				if err := mgr.RunBackup(); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				json.NewEncoder(w).Encode(map[string]string{"status": "backup completed"})
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{"error": "backup not available"})
			}
		})
		mux.HandleFunc("/keygen", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")

			if !peerRegistry.ArePeersReady() {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{"error": "peers not ready"})
				return
			}

			// Parse optional wallet_id from request body
			var req struct {
				WalletID string `json:"wallet_id"`
			}
			if r.Body != nil {
				json.NewDecoder(r.Body).Decode(&req)
			}
			if req.WalletID == "" {
				// Generate a deterministic wallet ID from timestamp + node
				h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", nodeID, time.Now().UnixNano())))
				req.WalletID = hex.EncodeToString(h[:16])
			}

			walletID := req.WalletID

			// Subscribe to the result topic before triggering keygen
			resultTopic := fmt.Sprintf("mpc.mpc_keygen_result.%s", walletID)
			resultCh := make(chan *event.KeygenResultEvent, 1)
			unsub, err := pubSub.Subscribe(resultTopic, func(natMsg *nats.Msg) {
				var result event.KeygenResultEvent
				if err := json.Unmarshal(natMsg.Data, &result); err == nil {
					select {
					case resultCh <- &result:
					default:
					}
				}
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "failed to subscribe to result topic"})
				return
			}
			defer unsub.Unsubscribe()

			// Create and publish GenerateKeyMessage
			msg := types.GenerateKeyMessage{
				WalletID: walletID,
			}
			msgData, _ := json.Marshal(msg)

			if err := pubSub.Publish("mpc:generate", msgData); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("failed to publish keygen: %v", err)})
				return
			}

			logger.Info("Keygen triggered", "walletID", walletID)

			// Wait for result with 60s timeout
			select {
			case result := <-resultCh:
				resp := map[string]interface{}{
					"wallet_id":   result.WalletID,
					"result_type": result.ResultType,
				}
				if result.ResultType == event.ResultTypeSuccess {
					resp["ecdsa_pub_key"] = hex.EncodeToString(result.ECDSAPubKey)
					resp["eddsa_pub_key"] = hex.EncodeToString(result.EDDSAPubKey)
					// Derive Ethereum address from uncompressed ECDSA pubkey
					if len(result.ECDSAPubKey) >= 33 {
						resp["eth_address"] = pubKeyToEthAddress(result.ECDSAPubKey)
					}
				} else {
					resp["error"] = result.ErrorReason
					resp["error_code"] = result.ErrorCode
				}
				json.NewEncoder(w).Encode(resp)
			case <-time.After(60 * time.Second):
				w.WriteHeader(http.StatusGatewayTimeout)
				json.NewEncoder(w).Encode(map[string]string{
					"error":     "keygen timed out after 60s",
					"wallet_id": walletID,
				})
			}
		})

		srv := &http.Server{Addr: apiAddr, Handler: mux}
		go func() {
			logger.Info("HTTP API server starting", "addr", apiAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP API server failed", err)
			}
		}()
		defer srv.Close()
	}

	// Start periodic backup with optional S3 upload
	backupDir := filepath.Join(dataDir, "backups")
	if zapKV, ok := factory.KVStore().(*kvstore.Store); ok && zapKV.Exec != nil {
		s3Cfg := backup.S3ConfigFromEnv(nodeID)
		backupMgr, err := backup.NewManager(zapKV.Exec, backupDir, nodeID, 5*time.Minute, s3Cfg)
		if err != nil {
			logger.Warn("Failed to create backup manager", "err", err)
		} else {
			backupMgr.Start()
			defer backupMgr.Stop()
			logger.Info("Backup manager started", "period", "5m", "s3", s3Cfg != nil)
		}
	}

	// Start Dashboard API server if PostgreSQL URL is provided
	apiDBURL := c.String("api-db")
	if apiDBURL == "" {
		apiDBURL = os.Getenv("MPC_API_DB")
	}
	if apiDBURL != "" {
		apiListenAddr := c.String("api-listen")
		jwtSecret := c.String("jwt-secret")
		if jwtSecret == "" {
			jwtSecret = os.Getenv("MPC_JWT_SECRET")
		}
		if jwtSecret == "" {
			jwtSecret = "change-me-in-production"
			logger.Warn("Using default JWT secret - NOT for production!")
		}

		apiKVAddr := c.String("api-kv")
		if apiKVAddr == "" {
			apiKVAddr = os.Getenv("MPC_API_KV")
		}
		database, err := db.New(apiDBURL, apiKVAddr)
		if err != nil {
			logger.Error("Failed to connect to dashboard database", err)
		} else {
			defer database.Close()
			{
				mpcBackend := &ConsensusMPCBackend{
					pubSub:       pubSub,
					peerRegistry: peerRegistry,
					factory:      factory,
					keyInfoStore: factory.KeyInfoStore(),
					nodeID:       nodeID,
					threshold:    threshold,
				}

				apiServer := mpcapi.NewServer(database, mpcBackend, jwtSecret, apiListenAddr)
				apiServer.StartScheduler(ctx)

				logger.Info("Dashboard API server starting", "addr", apiListenAddr)
				_, apiErrCh := apiServer.Start()
				go func() {
					if err := <-apiErrCh; err != nil {
						logger.Error("Dashboard API server failed", err)
					}
				}()
				defer apiServer.Shutdown(context.Background())

				logger.Info("Dashboard API ready", "addr", apiListenAddr)
			}
		}
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Warn("Shutdown signal received, stopping...")
	return nil
}

// ConsensusMPCBackend implements api.MPCBackend using the consensus transport.
type ConsensusMPCBackend struct {
	pubSub       *ConsensusPubSubAdapter
	peerRegistry *ConsensusPeerRegistry
	factory      *transport.Factory
	keyInfoStore *transport.KeyInfoStore
	nodeID       string
	threshold    int
}

func (b *ConsensusMPCBackend) TriggerKeygen(walletID string) (*mpcapi.KeygenResult, error) {
	if walletID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", b.nodeID, time.Now().UnixNano())))
		walletID = hex.EncodeToString(h[:16])
	}

	resultTopic := fmt.Sprintf("mpc.mpc_keygen_result.%s", walletID)
	resultCh := make(chan *event.KeygenResultEvent, 1)
	unsub, err := b.pubSub.Subscribe(resultTopic, func(natMsg *nats.Msg) {
		var result event.KeygenResultEvent
		if err := json.Unmarshal(natMsg.Data, &result); err == nil {
			select {
			case resultCh <- &result:
			default:
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to result topic: %w", err)
	}
	defer unsub.Unsubscribe()

	msg := types.GenerateKeyMessage{WalletID: walletID}
	msgData, _ := json.Marshal(msg)
	if err := b.pubSub.Publish("mpc:generate", msgData); err != nil {
		return nil, fmt.Errorf("failed to publish keygen: %w", err)
	}

	select {
	case result := <-resultCh:
		if result.ResultType != event.ResultTypeSuccess {
			return nil, fmt.Errorf("keygen failed: %s", result.ErrorReason)
		}
		ethAddr := ""
		if len(result.ECDSAPubKey) >= 32 {
			ethAddr = pubKeyToEthAddress(result.ECDSAPubKey)
		}
		return &mpcapi.KeygenResult{
			WalletID:    result.WalletID,
			ECDSAPubKey: hex.EncodeToString(result.ECDSAPubKey),
			EDDSAPubKey: hex.EncodeToString(result.EDDSAPubKey),
			EthAddress:  ethAddr,
		}, nil
	case <-time.After(120 * time.Second):
		return nil, fmt.Errorf("keygen timed out after 120s")
	}
}

func (b *ConsensusMPCBackend) TriggerSign(walletID string, payload []byte) (*mpcapi.SignResult, error) {
	txID := fmt.Sprintf("sign-%d", time.Now().UnixNano())
	resultTopic := fmt.Sprintf("mpc.mpc_signing_result.%s", walletID)
	resultCh := make(chan json.RawMessage, 1)
	unsub, err := b.pubSub.Subscribe(resultTopic, func(natMsg *nats.Msg) {
		select {
		case resultCh <- natMsg.Data:
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to signing result: %w", err)
	}
	defer unsub.Unsubscribe()

	// Look up key type from key info store
	keyType := types.KeyTypeSecp256k1 // default for ECDSA
	if b.keyInfoStore != nil {
		if info, err := b.keyInfoStore.Get(walletID); err == nil && info.KeyType != "" {
			keyType = types.KeyType(info.KeyType)
		}
	}
	// Normalize legacy key type names
	switch keyType {
	case "ecdsa", "ECDSA":
		keyType = types.KeyTypeSecp256k1
	case "eddsa", "EDDSA":
		keyType = types.KeyTypeEd25519
	}

	msg := types.SignTxMessage{
		KeyType:  keyType,
		WalletID: walletID,
		TxID:     txID,
		Tx:       payload,
	}
	msgData, _ := json.Marshal(msg)
	if err := b.pubSub.Publish("mpc:sign", msgData); err != nil {
		return nil, fmt.Errorf("failed to publish sign request: %w", err)
	}

	select {
	case data := <-resultCh:
		var result struct {
			ResultType        string `json:"result_type"`
			ErrorReason       string `json:"error_reason"`
			R                 []byte `json:"r"`
			S                 []byte `json:"s"`
			SignatureRecovery []byte `json:"signature_recovery"`
			Signature         []byte `json:"signature"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal signing result: %w", err)
		}
		if result.ResultType == "error" {
			return nil, fmt.Errorf("MPC signing failed: %s", result.ErrorReason)
		}
		sigR := hex.EncodeToString(result.R)
		sigS := hex.EncodeToString(result.S)
		var sigHex string
		if len(result.Signature) > 0 {
			sigHex = hex.EncodeToString(result.Signature)
		}
		return &mpcapi.SignResult{R: sigR, S: sigS, Signature: sigHex}, nil
	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("signing timed out after 60s")
	}
}

func (b *ConsensusMPCBackend) TriggerReshare(walletID string, newThreshold int, newParticipants []string) error {
	msg := map[string]interface{}{
		"wallet_id":        walletID,
		"new_threshold":    newThreshold,
		"new_participants": newParticipants,
	}
	msgData, _ := json.Marshal(msg)
	return b.pubSub.Publish("mpc:reshare", msgData)
}

func (b *ConsensusMPCBackend) GetClusterStatus() *mpcapi.ClusterStatus {
	ready := b.peerRegistry.ArePeersReady()
	connected := b.factory.Transport().GetPeers()
	return &mpcapi.ClusterStatus{
		NodeID:         b.nodeID,
		Mode:           "consensus",
		ExpectedPeers:  len(b.peerRegistry.peerIDs),
		ConnectedPeers: len(connected),
		Ready:          ready,
		Threshold:      b.threshold,
		Version:        Version,
	}
}

// loadOrGenerateIdentity loads or generates Ed25519 identity
func loadOrGenerateIdentity(keysDir, nodeID string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	identityPath := filepath.Join(keysDir, nodeID+"_identity.json")

	// Try to load existing identity
	data, err := os.ReadFile(identityPath)
	if err == nil {
		var identityData struct {
			NodeID     string `json:"node_id"`
			PublicKey  string `json:"public_key"`
			PrivateKey string `json:"private_key"`
		}
		if err := json.Unmarshal(data, &identityData); err == nil {
			privKeyBytes, err := hex.DecodeString(identityData.PrivateKey)
			if err == nil && len(privKeyBytes) == ed25519.PrivateKeySize {
				privKey := ed25519.PrivateKey(privKeyBytes)
				pubKey := privKey.Public().(ed25519.PublicKey)
				logger.Info("Loaded existing identity", "nodeID", nodeID)
				return privKey, pubKey, nil
			}
		}
	}

	// Generate new identity
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	// Save identity
	identityData := map[string]string{
		"node_id":     nodeID,
		"public_key":  hex.EncodeToString(pubKey),
		"private_key": hex.EncodeToString(privKey),
	}
	data, err = json.MarshalIndent(identityData, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(identityPath, data, 0600); err != nil {
		return nil, nil, err
	}

	logger.Info("Generated new identity", "nodeID", nodeID)
	return privKey, pubKey, nil
}

// ConsensusIdentityStore implements identity.Store for consensus mode
type ConsensusIdentityStore struct {
	nodeID          string
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey
	initiatorPubKey ed25519.PublicKey
	publicKeys      map[string][]byte
	mu              sync.RWMutex
}

func NewConsensusIdentityStore(nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *ConsensusIdentityStore {
	s := &ConsensusIdentityStore{
		nodeID:     nodeID,
		privateKey: privKey,
		publicKey:  pubKey,
		publicKeys: make(map[string][]byte),
	}
	s.publicKeys[nodeID] = pubKey

	// Load the event initiator public key from viper config.
	// This Ed25519 public key is used to verify that inbound event
	// messages (keygen, signing, reshare) originated from the authorized
	// initiator and have not been tampered with.
	if initiatorHex := viper.GetString("event_initiator_pubkey"); initiatorHex != "" {
		if decoded, err := hex.DecodeString(initiatorHex); err == nil && len(decoded) == ed25519.PublicKeySize {
			s.initiatorPubKey = ed25519.PublicKey(decoded)
		}
	}

	return s
}

func (s *ConsensusIdentityStore) GetPublicKey(nodeID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if key, ok := s.publicKeys[nodeID]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("public key not found for node: %s", nodeID)
}

func (s *ConsensusIdentityStore) VerifyInitiatorMessage(msg types.InitiatorMessage) error {
	if s.initiatorPubKey == nil {
		return fmt.Errorf("no initiator public key configured; cannot verify message")
	}

	// Reconstruct the canonical payload that was signed (excludes the
	// signature field itself).
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("failed to get raw message data: %w", err)
	}

	sig := msg.Sig()
	if len(sig) == 0 {
		return fmt.Errorf("message has no signature")
	}

	if !ed25519.Verify(s.initiatorPubKey, raw, sig) {
		return fmt.Errorf("invalid Ed25519 signature from initiator")
	}

	return nil
}

func (s *ConsensusIdentityStore) AddPeerPublicKey(nodeID string, pubKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicKeys[nodeID] = pubKey
}

// ConsensusPubSubAdapter adapts transport.PubSub to messaging.PubSub
type ConsensusPubSubAdapter struct {
	pubsub *transport.PubSub
}

func NewConsensusPubSubAdapter(pubsub *transport.PubSub) *ConsensusPubSubAdapter {
	return &ConsensusPubSubAdapter{pubsub: pubsub}
}

func (a *ConsensusPubSubAdapter) Publish(topic string, data []byte) error {
	return a.pubsub.Publish(topic, data)
}

func (a *ConsensusPubSubAdapter) PublishWithReply(topic, reply string, data []byte, headers map[string]string) error {
	return a.pubsub.PublishWithReply(topic, reply, data, headers)
}

func (a *ConsensusPubSubAdapter) Subscribe(topic string, handler func(msg *nats.Msg)) (messaging.Subscription, error) {
	sub, err := a.pubsub.Subscribe(topic, func(msg *transport.NATSMsg) {
		// Convert transport.NATSMsg to nats.Msg
		natsMsg := &nats.Msg{
			Subject: msg.Subject,
			Reply:   msg.Reply,
			Data:    msg.Data,
			Header:  nats.Header(msg.Header),
		}
		handler(natsMsg)
	})
	if err != nil {
		return nil, err
	}
	return &consensusSubscription{sub: sub}, nil
}

type consensusSubscription struct {
	sub *transport.Subscription
}

func (s *consensusSubscription) Unsubscribe() error {
	return s.sub.Unsubscribe()
}

// ConsensusPeerRegistry adapts transport.Registry to mpc.PeerRegistry
type ConsensusPeerRegistry struct {
	registry *transport.Registry
	nodeID   string
	peerIDs  []string
}

func NewConsensusPeerRegistry(registry *transport.Registry, nodeID string, peerIDs []string) *ConsensusPeerRegistry {
	return &ConsensusPeerRegistry{
		registry: registry,
		nodeID:   nodeID,
		peerIDs:  peerIDs,
	}
}

func (r *ConsensusPeerRegistry) Ready() error {
	return r.registry.Ready()
}

func (r *ConsensusPeerRegistry) Resign() error {
	return r.registry.Resign()
}

func (r *ConsensusPeerRegistry) WatchPeersReady() {
	r.registry.WatchPeersReady()
}

func (r *ConsensusPeerRegistry) ArePeersReady() bool {
	return r.registry.ArePeersReady()
}

func (r *ConsensusPeerRegistry) GetReadyPeersCount() int64 {
	return r.registry.GetReadyPeersCount()
}

func (r *ConsensusPeerRegistry) GetTotalPeersCount() int64 {
	return int64(len(r.peerIDs) + 1) // peers + self
}

func (r *ConsensusPeerRegistry) GetReadyPeersIncludeSelf() []string {
	return r.registry.GetReadyPeersIncludeSelf()
}

// ConsensusKeyInfoStore adapts transport.KeyInfoStore to keyinfo.Store
type ConsensusKeyInfoStore struct {
	store        *transport.KeyInfoStore
	peerRegistry *ConsensusPeerRegistry
}

func NewConsensusKeyInfoStore(store *transport.KeyInfoStore, peerRegistry *ConsensusPeerRegistry) *ConsensusKeyInfoStore {
	return &ConsensusKeyInfoStore{store: store, peerRegistry: peerRegistry}
}

func (s *ConsensusKeyInfoStore) Get(walletID string) (*keyinfo.KeyInfo, error) {
	info, err := s.store.Get(walletID)
	if err != nil {
		return nil, err
	}
	// Convert transport.KeyInfo to keyinfo.KeyInfo
	// Populate ParticipantPeerIDs from peer registry (all ready peers including self)
	participantPeerIDs := s.peerRegistry.GetReadyPeersIncludeSelf()
	return &keyinfo.KeyInfo{
		ParticipantPeerIDs: participantPeerIDs,
		Threshold:          info.Threshold,
		Version:            1, // Default version
	}, nil
}

func (s *ConsensusKeyInfoStore) Save(walletID string, info *keyinfo.KeyInfo) error {
	return s.store.RegisterKey(walletID, "secp256k1", info.Threshold, "", "", nil)
}

// ConsensusMessageQueue adapts transport for messaging.MessageQueue
type ConsensusMessageQueue struct {
	transport *transport.Transport
	nodeID    string
	queueType string
	handlers  map[string]func([]byte) error
	mu        sync.RWMutex
}

func NewConsensusMessageQueue(t *transport.Transport, nodeID, queueType string) *ConsensusMessageQueue {
	return &ConsensusMessageQueue{
		transport: t,
		nodeID:    nodeID,
		queueType: queueType,
		handlers:  make(map[string]func([]byte) error),
	}
}

func (q *ConsensusMessageQueue) Enqueue(topic string, message []byte, options *messaging.EnqueueOptions) error {
	// Broadcast the message via transport's Publish method
	return q.transport.Publish(topic, message)
}

func (q *ConsensusMessageQueue) Dequeue(topic string, handler func(message []byte) error) error {
	q.mu.Lock()
	q.handlers[topic] = handler
	q.mu.Unlock()
	// In consensus mode, messages are delivered via PubSub subscriptions
	// The handler will be called when messages arrive
	return nil
}

func (q *ConsensusMessageQueue) Close() {
	// Nothing to close in consensus mode
}

// pubKeyToEthAddress derives an Ethereum address from an ECDSA public key.
// Accepts compressed (33 bytes), uncompressed (65 bytes), or raw x-coordinate (32 bytes).
func pubKeyToEthAddress(pubKey []byte) string {
	var xyBytes []byte // 64 bytes: X(32) || Y(32)
	switch len(pubKey) {
	case 65:
		// Uncompressed: 0x04 || X(32) || Y(32)
		xyBytes = pubKey[1:]
	case 33:
		// Compressed: 0x02/0x03 || X(32) — decompress via secp256k1
		x, y := ellipticUnmarshalCompressed(pubKey)
		if x == nil {
			return ""
		}
		xyBytes = append(x.Bytes(), y.Bytes()...)
	case 32:
		// Raw x-coordinate only — try decompressing with 0x02 prefix (even y)
		compressed := append([]byte{0x02}, pubKey...)
		x, y := ellipticUnmarshalCompressed(compressed)
		if x == nil {
			// Try odd y
			compressed[0] = 0x03
			x, y = ellipticUnmarshalCompressed(compressed)
		}
		if x == nil {
			return ""
		}
		xBytes := make([]byte, 32)
		yBytes := make([]byte, 32)
		xB := x.Bytes()
		yB := y.Bytes()
		copy(xBytes[32-len(xB):], xB)
		copy(yBytes[32-len(yB):], yB)
		xyBytes = append(xBytes, yBytes...)
	default:
		// Try as hex string
		decoded, err := hex.DecodeString(string(pubKey))
		if err == nil && len(decoded) > 0 {
			return pubKeyToEthAddress(decoded)
		}
		return ""
	}
	if len(xyBytes) != 64 {
		return ""
	}
	hash := sha3.NewLegacyKeccak256()
	hash.Write(xyBytes)
	addrBytes := hash.Sum(nil)[12:]
	return "0x" + hex.EncodeToString(addrBytes)
}

// ellipticUnmarshalCompressed decompresses a secp256k1 compressed public key.
func ellipticUnmarshalCompressed(compressed []byte) (*big.Int, *big.Int) {
	if len(compressed) != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03) {
		return nil, nil
	}
	curve := crypto_elliptic.P256() // Use P256 as base; secp256k1 params below
	// secp256k1 curve parameters
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	x := new(big.Int).SetBytes(compressed[1:33])
	// y² = x³ + 7 (mod p) for secp256k1
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)
	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, p)
	// ModSqrt
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil, nil
	}
	// Check parity
	if y.Bit(0) != uint(compressed[0]&1) {
		y.Sub(p, y)
	}
	_ = curve // suppress unused
	return x, y
}

// runAPIOnly starts only the Dashboard API server without any MPC transport.
// This is used for the cloud dashboard deployment where MPC operations are
// forwarded to the MPC nodes separately.
func runAPIOnly(ctx context.Context, c *cli.Command) error {
	debug := c.Bool("debug")
	logger.Init("api", debug)

	dbURL := c.String("db")
	if dbURL == "" {
		return fmt.Errorf("--db (or DATABASE_URL env) is required")
	}
	listenAddr := c.String("listen")
	jwtSecret := c.String("jwt-secret")
	if jwtSecret == "" {
		return fmt.Errorf("--jwt-secret (or JWT_SECRET env) is required")
	}

	logger.Info("Starting Dashboard API server (standalone)", "addr", listenAddr)

	database, err := db.New(dbURL, "")
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	logger.Info("Database connected")

	// Determine MPC backend: if cluster-url is provided, forward to the cluster;
	// otherwise use a stub that returns descriptive errors.
	clusterURL := c.String("cluster-url")
	clusterAPIKey := c.String("cluster-api-key")

	var mpcBackend mpcapi.MPCBackend
	if clusterURL != "" {
		mpcBackend = newAPIOnlyMPCBackend(clusterURL, clusterAPIKey)
		logger.Info("API-only mode: forwarding MPC operations to cluster", "url", clusterURL)
	} else {
		mpcBackend = &stubMPCBackend{}
		logger.Warn("API-only mode: no MPC_CLUSTER_URL set, MPC operations will fail")
	}

	apiServer := mpcapi.NewServer(database, mpcBackend, jwtSecret, listenAddr)
	apiServer.StartScheduler(ctx)

	_, apiErrCh := apiServer.Start()
	logger.Info("Dashboard API ready", "addr", listenAddr)

	// Wait for shutdown signal or server error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logger.Warn("Shutdown signal received", "signal", sig)
	case err := <-apiErrCh:
		if err != nil {
			return fmt.Errorf("API server failed: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return apiServer.Shutdown(shutdownCtx)
}

// stubMPCBackend returns errors for MPC operations when no cluster URL is configured.
type stubMPCBackend struct{}

func (s *stubMPCBackend) TriggerKeygen(walletID string) (*mpcapi.KeygenResult, error) {
	return nil, fmt.Errorf("MPC operations not available: set MPC_CLUSTER_URL to enable forwarding")
}

func (s *stubMPCBackend) TriggerSign(walletID string, payload []byte) (*mpcapi.SignResult, error) {
	return nil, fmt.Errorf("MPC operations not available: set MPC_CLUSTER_URL to enable forwarding")
}

func (s *stubMPCBackend) TriggerReshare(walletID string, newThreshold int, newParticipants []string) error {
	return fmt.Errorf("MPC operations not available: set MPC_CLUSTER_URL to enable forwarding")
}

func (s *stubMPCBackend) GetClusterStatus() *mpcapi.ClusterStatus {
	return &mpcapi.ClusterStatus{
		NodeID:  "api-only",
		Mode:    "api-only",
		Ready:   false,
		Version: Version,
	}
}

// apiOnlyMPCBackend forwards MPC operations to the actual MPC cluster via HTTP.
type apiOnlyMPCBackend struct {
	clusterURL string
	apiKey     string
	httpClient *http.Client
}

func newAPIOnlyMPCBackend(clusterURL, apiKey string) *apiOnlyMPCBackend {
	// Strip trailing slash from cluster URL
	clusterURL = strings.TrimRight(clusterURL, "/")
	return &apiOnlyMPCBackend{
		clusterURL: clusterURL,
		apiKey:     apiKey,
		httpClient: &http.Client{
			Timeout: 120 * time.Second, // MPC keygen can take ~30s; allow generous timeout
		},
	}
}

// doRequest sends an HTTP request to the MPC cluster and decodes the JSON response.
func (a *apiOnlyMPCBackend) doRequest(method, path string, reqBody interface{}, respBody interface{}) error {
	var bodyReader *strings.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	} else {
		bodyReader = strings.NewReader("")
	}

	url := a.clusterURL + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("X-API-Key", a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cluster request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return fmt.Errorf("cluster returned %d: %s", resp.StatusCode, errBody.Error)
		}
		return fmt.Errorf("cluster returned status %d", resp.StatusCode)
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("failed to decode cluster response: %w", err)
		}
	}
	return nil
}

func (a *apiOnlyMPCBackend) TriggerKeygen(walletID string) (*mpcapi.KeygenResult, error) {
	reqBody := map[string]string{"wallet_id": walletID}
	var result mpcapi.KeygenResult
	if err := a.doRequest("POST", "/api/v1/keygen", reqBody, &result); err != nil {
		return nil, fmt.Errorf("keygen forwarding failed: %w", err)
	}
	return &result, nil
}

func (a *apiOnlyMPCBackend) TriggerSign(walletID string, payload []byte) (*mpcapi.SignResult, error) {
	reqBody := map[string]interface{}{
		"wallet_id": walletID,
		"payload":   hex.EncodeToString(payload),
	}
	var result mpcapi.SignResult
	if err := a.doRequest("POST", "/api/v1/sign", reqBody, &result); err != nil {
		return nil, fmt.Errorf("sign forwarding failed: %w", err)
	}
	return &result, nil
}

func (a *apiOnlyMPCBackend) TriggerReshare(walletID string, newThreshold int, newParticipants []string) error {
	reqBody := map[string]interface{}{
		"wallet_id":        walletID,
		"new_threshold":    newThreshold,
		"new_participants": newParticipants,
	}
	if err := a.doRequest("POST", "/api/v1/reshare", reqBody, nil); err != nil {
		return fmt.Errorf("reshare forwarding failed: %w", err)
	}
	return nil
}

func (a *apiOnlyMPCBackend) GetClusterStatus() *mpcapi.ClusterStatus {
	var status mpcapi.ClusterStatus
	if err := a.doRequest("GET", "/api/v1/status", nil, &status); err != nil {
		logger.Warn("Failed to get cluster status", "err", err, "url", a.clusterURL)
		return &mpcapi.ClusterStatus{
			NodeID:  "api-only",
			Mode:    "api-only-proxy",
			Ready:   false,
			Version: Version,
		}
	}
	return &status
}
