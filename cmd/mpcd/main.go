package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/luxfi/mpc/pkg/config"
	"github.com/luxfi/mpc/pkg/constant"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/eventconsumer"
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
	Version                    = "0.3.1"
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

	badgerKV := NewBadgerKV(nodeName, nodeID)
	defer badgerKV.Close()

	// Wrap BadgerKV with KMS-enabled store if configured
	var kvStore kvstore.KVStore = badgerKV
	kmsEnabledStore, err := mpc.NewKMSEnabledKVStore(badgerKV, nodeID)
	if err != nil {
		logger.Warn("Failed to create KMS-enabled store, using regular BadgerDB", "error", err)
	} else {
		kvStore = kmsEnabledStore
		logger.Info("Using KMS-enabled storage for sensitive keys")
	}

	// Start background backup job
	backupEnabled := viper.GetBool("backup_enabled")
	if backupEnabled {
		backupPeriodSeconds := viper.GetInt("backup_period_seconds")
		stopBackup := StartPeriodicBackup(ctx, badgerKV, backupPeriodSeconds)
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
	fmt.Println("WARNING: Please back up your Badger DB password in a secure location.")
	fmt.Println("If you lose this password, you will permanently lose access to your data!")

	// Prompt for badger password with confirmation
	var badgerPass []byte
	var confirmPass []byte
	var err error

	for {
		fmt.Print("Enter Badger DB password: ")
		badgerPass, err = term.ReadPassword(syscall.Stdin)
		if err != nil {
			logger.Fatal("Failed to read badger password", err)
		}
		fmt.Println() // Add newline after password input

		if len(badgerPass) == 0 {
			fmt.Println("Password cannot be empty. Please try again.")
			continue
		}

		fmt.Print("Confirm Badger DB password: ")
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

	viper.Set("badger_password", string(badgerPass))

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
	if viper.GetString("badger_password") == "" {
		logger.Fatal("Badger password is required", nil)
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

func NewBadgerKV(nodeName, nodeID string) *kvstore.BadgerKVStore {
	// Badger KV DB
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

	// Create BadgerConfig struct
	config := kvstore.BadgerConfig{
		NodeID:              nodeName,
		EncryptionKey:       []byte(viper.GetString("badger_password")),
		BackupEncryptionKey: []byte(viper.GetString("badger_password")), // Using same key for backup encryption
		BackupDir:           backupDir,
		DBPath:              dbPath,
	}

	badgerKv, err := kvstore.NewBadgerKVStore(config)
	if err != nil {
		logger.Fatal("Failed to create badger kv store", err)
	}
	logger.Info("Connected to badger kv store", "path", dbPath, "backup_dir", backupDir)
	return badgerKv
}

func StartPeriodicBackup(ctx context.Context, badgerKV *kvstore.BadgerKVStore, periodSeconds int) func() {
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
				logger.Info("Running periodic BadgerDB backup...")
				err := badgerKV.Backup()
				if err != nil {
					logger.Error("Periodic BadgerDB backup failed", err)
				} else {
					logger.Info("Periodic BadgerDB backup completed successfully")
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
	threshold := int(c.Int("threshold"))
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

	// Get badger password from environment or prompt
	badgerPassword := os.Getenv("LUX_MPC_PASSWORD")
	if badgerPassword == "" {
		badgerPassword = viper.GetString("badger_password")
	}
	if badgerPassword == "" {
		// Generate a random password for development
		logger.Warn("No badger password set, using default (NOT for production!)")
		badgerPassword = "dev-password-change-me"
	}

	// Create transport factory
	factoryCfg := transport.FactoryConfig{
		NodeID:         nodeID,
		ListenAddr:     listenAddr,
		Peers:          peerMap,
		PrivateKey:     privKey,
		PublicKey:      pubKey,
		BadgerPath:     filepath.Join(dataDir, "db"),
		BadgerPassword: badgerPassword,
		BackupDir:      filepath.Join(dataDir, "backups"),
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
		NewConsensusKeyInfoStore(factory.KeyInfoStore()),
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

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Warn("Shutdown signal received, stopping...")
	return nil
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
	nodeID     string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	publicKeys map[string][]byte
	mu         sync.RWMutex
}

func NewConsensusIdentityStore(nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *ConsensusIdentityStore {
	s := &ConsensusIdentityStore{
		nodeID:     nodeID,
		privateKey: privKey,
		publicKey:  pubKey,
		publicKeys: make(map[string][]byte),
	}
	s.publicKeys[nodeID] = pubKey
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
	// In consensus mode, verify using the message's embedded signature
	// For now, accept all messages (TODO: implement proper verification)
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
	store *transport.KeyInfoStore
}

func NewConsensusKeyInfoStore(store *transport.KeyInfoStore) *ConsensusKeyInfoStore {
	return &ConsensusKeyInfoStore{store: store}
}

func (s *ConsensusKeyInfoStore) Get(walletID string) (*keyinfo.KeyInfo, error) {
	info, err := s.store.Get(walletID)
	if err != nil {
		return nil, err
	}
	// Convert transport.KeyInfo to keyinfo.KeyInfo
	// The keyinfo.KeyInfo has different fields (ParticipantPeerIDs, Threshold, Version)
	return &keyinfo.KeyInfo{
		Threshold: info.Threshold,
		Version:   1, // Default version
	}, nil
}

func (s *ConsensusKeyInfoStore) Save(walletID string, info *keyinfo.KeyInfo) error {
	return s.store.RegisterKey(walletID, "ecdsa", info.Threshold, "", "", nil)
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
