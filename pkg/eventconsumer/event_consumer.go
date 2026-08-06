package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"

	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/luxfi/mpc/pkg/types"
)

const (
	MPCGenerateEvent = "mpc:generate"
	MPCSignEvent     = "mpc:sign"
	MPCReshareEvent  = "mpc:reshare"

	DefaultConcurrentKeygen    = 2
	DefaultSessionStartupDelay = 500

	KeyGenTimeOut = 120 * time.Second

	// Ed25519KeyGenTimeOut bounds the Ed25519 leg on its own, so the expensive
	// secp256k1 leg cannot starve it. FROST keygen is three rounds with no heavy
	// primitives — it is bounded by network round-trips, not computation — so
	// this is generous rather than tight.
	Ed25519KeyGenTimeOut = 60 * time.Second
)

type EventConsumer interface {
	Run()
	Close() error
}

type eventConsumer struct {
	node         *mpc.Node
	pubsub       messaging.PubSub
	mpcThreshold int

	genKeyResultQueue  messaging.MessageQueue
	signingResultQueue messaging.MessageQueue
	reshareResultQueue messaging.MessageQueue

	keyGenerationSub messaging.Subscription
	signingSub       messaging.Subscription
	reshareSub       messaging.Subscription
	identityStore    identity.Store
	keyinfoStore     keyinfo.Store

	msgBuffer           chan *nats.Msg
	maxConcurrentKeygen int

	// Track active sessions with timestamps for cleanup
	activeSessions  map[string]time.Time // Maps "walletID-txID" to creation time
	sessionsLock    sync.RWMutex
	cleanupInterval time.Duration // How often to run cleanup
	sessionTimeout  time.Duration // How long before a session is considered stale
	cleanupStopChan chan struct{} // Signal to stop cleanup goroutine
}

func NewEventConsumer(
	node *mpc.Node,
	pubsub messaging.PubSub,
	genKeyResultQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
	reshareResultQueue messaging.MessageQueue,
	identityStore identity.Store,
) EventConsumer {
	maxConcurrentKeygen := viper.GetInt("max_concurrent_keygen")
	if maxConcurrentKeygen == 0 {
		maxConcurrentKeygen = DefaultConcurrentKeygen
	}

	ec := &eventConsumer{
		node:                node,
		pubsub:              pubsub,
		genKeyResultQueue:   genKeyResultQueue,
		signingResultQueue:  signingResultQueue,
		reshareResultQueue:  reshareResultQueue,
		activeSessions:      make(map[string]time.Time),
		cleanupInterval:     5 * time.Minute,  // Run cleanup every 5 minutes
		sessionTimeout:      30 * time.Minute, // Consider sessions older than 30 minutes stale
		cleanupStopChan:     make(chan struct{}),
		mpcThreshold:        viper.GetInt("mpc_threshold"),
		maxConcurrentKeygen: maxConcurrentKeygen,
		identityStore:       identityStore,
		keyinfoStore:        node.KeyInfoStore(),
		msgBuffer:           make(chan *nats.Msg, 100),
	}

	go ec.startKeyGenEventWorker()
	// Start background cleanup goroutine
	go ec.sessionCleanupRoutine()

	return ec
}

func (ec *eventConsumer) Run() {
	err := ec.consumeKeyGenerationEvent()
	if err != nil {
		log.Fatal("Failed to consume key reconstruction event", err)
	}

	err = ec.consumeTxSigningEvent()
	if err != nil {
		log.Fatal("Failed to consume tx signing event", err)
	}

	err = ec.consumeReshareEvent()
	if err != nil {
		log.Fatal("Failed to consume reshare event", err)
	}

	logger.Info("MPC Event consumer started...!")
}

// handleKeyGenEvent mints a wallet's key set and publishes it.
//
// A wallet is not one key. Chains disagree about curves, and
// types.KeyTypeForNetwork is the single table recording which chain wants which,
// so a wallet needs one key per curve its networks use and a single keygen
// request mints them all. This function is the only place that decides which
// ceremonies run, which is what keeps every site downstream from having to know
// or guess a curve.
//
// The two legs do not have equal standing:
//
//   - secp256k1 (CGGMP21) backs EVM, Bitcoin, LUX and XRPL. Its failure fails the
//     wallet.
//   - Ed25519 (FROST) backs Solana and TON. Its failure is deliberately NOT
//     fatal: the wallet is published without eddsa_pub_key, which suppresses
//     sol_address downstream. A wallet that cannot receive Solana is an
//     inconvenience; a wallet that receives Solana at an address the ring cannot
//     sign for has lost the funds permanently. Only the first is recoverable, so
//     the Ed25519 leg fails closed and the wallet survives without it.
//
// sr25519 (Polkadot/Kusama) appears in the network table but has no leg here, so
// DOT/KSM wallets still cannot be minted. That gap predates this function and is
// left visible rather than papered over.
//
// The order is load-bearing and must not be changed or parallelised. Only the
// CGGMP21 session writes the wallet's keyinfo record (its threshold and
// participant set); the Ed25519 session never does. CreateEdDSASignSession reads
// that record to decide whether it has enough signers, so an Ed25519 key minted
// without the CGGMP21 leg having completed first would be unsignable — the exact
// outcome this whole change exists to prevent. Running secp256k1 first, and
// abandoning the wallet if it fails, is what guarantees the record exists.
//
// Each leg gets its OWN deadline rather than sharing one. A single budget across
// two sequential ceremonies is not shared fairly: CGGMP21 is the expensive leg
// (Paillier keygen and its proofs), so it would routinely consume most of the
// budget and starve the Ed25519 leg into a systematic timeout — turning "Solana
// is supported" into "Solana works when the ring is idle". Separate deadlines
// also mean the secp256k1 leg keeps exactly the budget it had before this
// change, so nothing that worked previously became slower or less reliable.
func (ec *eventConsumer) handleKeyGenEvent(natMsg *nats.Msg) {
	raw := natMsg.Data
	var msg types.GenerateKeyMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		logger.Error("Failed to unmarshal keygen message", err)
		ec.handleKeygenSessionError("", err, "Failed to unmarshal keygen message", natMsg)
		return
	}

	if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
		logger.Error("Failed to verify initiator message", err)
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to verify initiator message", natMsg)
		return
	}

	ec.trackSession(msg.OrgID, msg.WalletID, "")
	defer ec.untrackSession(msg.OrgID, msg.WalletID, "")

	result := &event.KeygenResultEvent{
		WalletID:   msg.WalletID,
		ResultType: event.ResultTypeSuccess,
	}

	secpCtx, cancelSecp := context.WithTimeout(context.Background(), KeyGenTimeOut)
	ecdsaPubKey, err := ec.runCGGMP21Keygen(secpCtx, msg.OrgID, msg.WalletID)
	cancelSecp()
	if err != nil {
		ec.handleKeygenSessionError(msg.WalletID, err, "CGGMP21 key generation failed", natMsg)
		return
	}
	result.ECDSAPubKey = ecdsaPubKey

	ed25519Ctx, cancelEd := context.WithTimeout(context.Background(), Ed25519KeyGenTimeOut)
	eddsaPubKey, err := ec.runEd25519Keygen(ed25519Ctx, msg.OrgID, msg.WalletID)
	cancelEd()
	if err != nil {
		logEd25519LegSkipped(msg.WalletID, err)
	} else {
		result.EDDSAPubKey = eddsaPubKey
	}

	// Nothing below this line may relax the curve check. If an EdDSA key is
	// present it must be a real Ed25519 key; otherwise drop it and publish the
	// wallet without one.
	if err := assertKeygenResultConsistent(result); err != nil {
		logEd25519LegSkipped(msg.WalletID, err)
		result.EDDSAPubKey = nil
	}

	payload, err := json.Marshal(result)
	if err != nil {
		logger.Error("Failed to marshal keygen success event", err)
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to marshal keygen success event", natMsg)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, msg.WalletID)
	if err := ec.genKeyResultQueue.Enqueue(
		key,
		payload,
		&messaging.EnqueueOptions{IdempotententKey: composeKeygenIdempotentKey(msg.WalletID, natMsg)},
	); err != nil {
		logger.Error("Failed to publish key generation success message", err)
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to publish key generation success message", natMsg)
		return
	}

	ec.sendReplyToRemoveMsg(natMsg)
	logger.Info("[COMPLETED KEY GEN] key generation completed",
		"walletID", msg.WalletID,
		"hasECDSAKey", len(result.ECDSAPubKey) > 0,
		"hasEd25519Key", len(result.EDDSAPubKey) > 0,
	)
}

// handleKeygenSessionError handles errors that occur during key generation
func (ec *eventConsumer) handleKeygenSessionError(walletID string, err error, contextMsg string, natMsg *nats.Msg) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)
	keygenResult := event.KeygenResultEvent{
		ResultType:  event.ResultTypeError,
		ErrorCode:   string(errorCode),
		WalletID:    walletID,
		ErrorReason: fullErrMsg,
	}

	keygenResultBytes, err := json.Marshal(keygenResult)
	if err != nil {
		logger.Error("Failed to marshal keygen result event", err,
			"walletID", walletID,
		)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, walletID)
	err = ec.genKeyResultQueue.Enqueue(key, keygenResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: composeKeygenIdempotentKey(walletID, natMsg),
	})
	if err != nil {
		logger.Error("Failed to enqueue keygen result event", err,
			"walletID", walletID,
			"payload", string(keygenResultBytes),
		)
	}
	ec.sendReplyToRemoveMsg(natMsg)
}

func (ec *eventConsumer) startKeyGenEventWorker() {
	// semaphore to limit concurrency
	semaphore := make(chan struct{}, ec.maxConcurrentKeygen)

	for natMsg := range ec.msgBuffer {
		semaphore <- struct{}{} // acquire a slot
		go func(msg *nats.Msg) {
			defer func() { <-semaphore }() // release the slot when done
			ec.handleKeyGenEvent(msg)
		}(natMsg)
	}
}

func (ec *eventConsumer) consumeKeyGenerationEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCGenerateEvent, func(natMsg *nats.Msg) {
		ec.msgBuffer <- natMsg
	})

	ec.keyGenerationSub = sub
	if err != nil {
		return err
	}
	return nil
}

func (ec *eventConsumer) consumeTxSigningEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCSignEvent, func(natMsg *nats.Msg) {
		raw := natMsg.Data
		var msg types.SignTxMessage
		err := json.Unmarshal(raw, &msg)
		if err != nil {
			logger.Error("Failed to unmarshal signing message", err)
			return
		}

		err = ec.identityStore.VerifyInitiatorMessage(&msg)
		if err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		logger.Info(
			"Received signing event",
			"waleltID",
			msg.WalletID,
			"type",
			msg.KeyType,
			"tx",
			msg.TxID,
			"Id",
			ec.node.ID(),
		)

		// Route signing to the correct handler based on key type
		switch msg.KeyType {
		case types.KeyTypeSecp256k1:
			ec.handleSigningEventCGGMP21(&msg, natMsg)
		case types.KeyTypeEd25519:
			ec.handleSigningEventFROST(&msg, natMsg)
		case types.KeyTypeSR25519:
			ec.handleSigningEventSR25519(&msg, natMsg)
		default:
			logger.Error("Unsupported key type for signing", nil,
				"walletID", msg.WalletID,
				"txID", msg.TxID,
				"keyType", msg.KeyType,
			)
			ec.handleSigningSessionError(
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				fmt.Errorf("unsupported key type: %v", msg.KeyType),
				"Unsupported key type",
				natMsg,
			)
		}
	})

	ec.signingSub = sub
	if err != nil {
		return err
	}

	return nil
}
func (ec *eventConsumer) handleSigningSessionError(walletID, txID, networkInternalCode string, err error, contextMsg string, natMsg *nats.Msg) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Signing session error",
		"walletID", walletID,
		"txID", txID,
		"networkInternalCode", networkInternalCode,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	signingResult := event.SigningResultEvent{
		ResultType:          event.ResultTypeError,
		ErrorCode:           errorCode,
		NetworkInternalCode: networkInternalCode,
		WalletID:            walletID,
		TxID:                txID,
		ErrorReason:         fullErrMsg,
	}

	signingResultBytes, err := json.Marshal(signingResult)
	if err != nil {
		logger.Error("Failed to marshal signing result event", err,
			"walletID", walletID,
			"txID", txID,
		)
		return
	}
	err = ec.signingResultQueue.Enqueue(event.SigningResultCompleteTopic, signingResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: txID,
	})
	if err != nil {
		logger.Error("Failed to enqueue signing result event", err,
			"walletID", walletID,
			"txID", txID,
			"payload", string(signingResultBytes),
		)
	}
	ec.sendReplyToRemoveMsg(natMsg)
}

func (ec *eventConsumer) sendReplyToRemoveMsg(natMsg *nats.Msg) {
	msg := natMsg.Data

	if natMsg.Reply == "" {
		logger.Warn("No reply inbox specified for sign success message", "msg", string(msg))
		return
	}

	err := ec.pubsub.Publish(natMsg.Reply, msg)
	if err != nil {
		logger.Error("Failed to reply message", err, "reply", natMsg.Reply)
		return
	}
}

func (ec *eventConsumer) consumeReshareEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCReshareEvent, func(natMsg *nats.Msg) {
		var msg types.ResharingMessage
		if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
			logger.Error("Failed to unmarshal resharing message", err)
			ec.handleReshareSessionError(msg.WalletID, msg.KeyType, msg.NewThreshold, err, "Failed to unmarshal resharing message")
			return
		}

		if msg.SessionID == "" {
			ec.handleReshareSessionError(
				msg.WalletID,
				msg.KeyType,
				msg.NewThreshold,
				errors.New("validation: session ID is empty"),
				"Session ID is empty",
			)
			return
		}

		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			ec.handleReshareSessionError(msg.WalletID, msg.KeyType, msg.NewThreshold, err, "Failed to verify initiator message")
			return
		}

		walletID := msg.WalletID
		keyType := msg.KeyType

		sessionType, err := sessionTypeFromKeyType(keyType)
		if err != nil {
			logger.Error("Failed to get session type", err)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to get session type")
			return
		}

		createSession := func(isNewPeer bool) (mpc.ReshareSession, error) {
			return ec.node.CreateReshareSession(
				sessionType,
				walletID,
				ec.mpcThreshold,
				msg.NewThreshold,
				msg.NodeIDs,
				isNewPeer,
				ec.reshareResultQueue,
				msg.OrgID,
			)
		}

		oldSession, err := createSession(false)
		if err != nil {
			logger.Error("Failed to create old reshare session", err, "walletID", walletID)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to create old reshare session")
			return
		}
		newSession, err := createSession(true)
		if err != nil {
			logger.Error("Failed to create new reshare session", err, "walletID", walletID)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to create new reshare session")
			return
		}

		if oldSession == nil && newSession == nil {
			logger.Info("Node is not participating in this reshare (neither old nor new)", "walletID", walletID)
			return
		}

		successEvent := &event.ResharingResultEvent{
			WalletID:     walletID,
			NewThreshold: msg.NewThreshold,
			KeyType:      msg.KeyType,
			ResultType:   event.ResultTypeSuccess,
		}

		var wg sync.WaitGroup
		ctx := context.Background()

		time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

		if oldSession != nil {
			ctxOld, doneOld := context.WithCancel(ctx)
			oldSession.Init()
			oldSession.ListenToIncomingMessageAsync()
			go oldSession.Reshare(doneOld)

			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctxOld.Done():
						return
					case err := <-oldSession.ErrChan():
						logger.Error("Old reshare session error", err)
						ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Old reshare session error")
						doneOld() // Cancel the context to stop this session
						return
					}
				}
			}()
		}

		if newSession != nil {
			ctxNew, doneNew := context.WithCancel(ctx)
			newSession.Init()
			newSession.ListenToIncomingMessageAsync()
			go newSession.Reshare(doneNew)

			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctxNew.Done():
						successEvent.PubKey = newSession.GetPubKeyResult()
						return
					case err := <-newSession.ErrChan():
						logger.Error("New reshare session error", err)
						ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "New reshare session error")
						doneNew() // Cancel the context to stop this session
						return
					}
				}
			}()
		}

		wg.Wait()

		logger.Info("Reshare session finished", "walletID", walletID, "pubKey", fmt.Sprintf("%x", successEvent.PubKey))

		if newSession != nil {
			successBytes, err := json.Marshal(successEvent)
			if err != nil {
				logger.Error("Failed to marshal reshare success event", err)
				ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to marshal reshare success event")
				return
			}

			key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, msg.SessionID)
			err = ec.reshareResultQueue.Enqueue(
				key,
				successBytes,
				&messaging.EnqueueOptions{
					IdempotententKey: key,
				})
			if err != nil {
				logger.Error("Failed to publish reshare success message", err)
				ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to publish reshare success message")
				return
			}
			logger.Info("[COMPLETED RESHARE] Successfully published", "walletID", walletID)
		} else {
			logger.Info("[COMPLETED RESHARE] Done (not a new party)", "walletID", walletID)
		}
	})

	ec.reshareSub = sub
	return err
}

// handleReshareSessionError handles errors that occur during reshare operations
func (ec *eventConsumer) handleReshareSessionError(
	walletID string,
	keyType types.KeyType,
	newThreshold int,
	err error,
	contextMsg string,
) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Reshare session error",
		"walletID", walletID,
		"keyType", keyType,
		"newThreshold", newThreshold,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	reshareResult := event.ResharingResultEvent{
		ResultType:   event.ResultTypeError,
		ErrorCode:    string(errorCode),
		WalletID:     walletID,
		KeyType:      keyType,
		NewThreshold: newThreshold,
		ErrorReason:  fullErrMsg,
	}

	reshareResultBytes, err := json.Marshal(reshareResult)
	if err != nil {
		logger.Error("Failed to marshal reshare result event", err,
			"walletID", walletID,
		)
		return
	}

	key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, walletID)
	err = ec.reshareResultQueue.Enqueue(key, reshareResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: key,
	})
	if err != nil {
		logger.Error("Failed to enqueue reshare result event", err,
			"walletID", walletID,
			"payload", string(reshareResultBytes),
		)
	}
}

// Add a cleanup routine that runs periodically
func (ec *eventConsumer) sessionCleanupRoutine() {
	ticker := time.NewTicker(ec.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ec.cleanupStaleSessions()
		case <-ec.cleanupStopChan:
			return
		}
	}
}

// Cleanup stale sessions
func (ec *eventConsumer) cleanupStaleSessions() {
	now := time.Now()
	ec.sessionsLock.Lock()
	defer ec.sessionsLock.Unlock()

	for sessionID, creationTime := range ec.activeSessions {
		if now.Sub(creationTime) > ec.sessionTimeout {
			delete(ec.activeSessions, sessionID)
		}
	}
}

// addSession marks a session as active with the current timestamp.
// orgID scopes the session to prevent cross-tenant collisions.
func (ec *eventConsumer) addSession(orgID, walletID, txID string) {
	sessionID := fmt.Sprintf("%s-%s-%s", orgID, walletID, txID)
	ec.sessionsLock.Lock()
	ec.activeSessions[sessionID] = time.Now()
	ec.sessionsLock.Unlock()
}

// trackSession tracks a new session, scoped by orgID.
func (ec *eventConsumer) trackSession(orgID, walletID, txID string) {
	sessionID := orgID + "-" + walletID
	if txID != "" {
		sessionID = fmt.Sprintf("%s-%s-%s", orgID, walletID, txID)
	}

	ec.sessionsLock.Lock()
	ec.activeSessions[sessionID] = time.Now()
	ec.sessionsLock.Unlock()
}

// untrackSession removes a session from tracking.
func (ec *eventConsumer) untrackSession(orgID, walletID, txID string) {
	sessionID := orgID + "-" + walletID
	if txID != "" {
		sessionID = fmt.Sprintf("%s-%s-%s", orgID, walletID, txID)
	}

	ec.sessionsLock.Lock()
	delete(ec.activeSessions, sessionID)
	ec.sessionsLock.Unlock()
}

// checkDuplicateSession checks if a session already exists.
// Returns true if the session is a duplicate. orgID scopes sessions per tenant.
func (ec *eventConsumer) checkDuplicateSession(orgID, walletID, txID string) bool {
	sessionID := fmt.Sprintf("%s-%s-%s", orgID, walletID, txID)

	// Check for duplicate
	ec.sessionsLock.RLock()
	_, isDuplicate := ec.activeSessions[sessionID]
	ec.sessionsLock.RUnlock()

	if isDuplicate {
		logger.Info("Duplicate signing request detected", "orgID", orgID, "walletID", walletID, "txID", txID)
		return true
	}

	return false
}

// Close and clean up
func (ec *eventConsumer) Close() error {
	// Signal cleanup routine to stop
	close(ec.cleanupStopChan)

	err := ec.keyGenerationSub.Unsubscribe()
	if err != nil {
		return err
	}
	err = ec.signingSub.Unsubscribe()
	if err != nil {
		return err
	}
	err = ec.reshareSub.Unsubscribe()
	if err != nil {
		return err
	}

	return nil
}

func sessionTypeFromKeyType(keyType types.KeyType) (mpc.SessionType, error) {
	switch keyType {
	case types.KeyTypeSecp256k1:
		return mpc.SessionTypeECDSA, nil
	case types.KeyTypeEd25519:
		return mpc.SessionTypeEDDSA, nil
	case types.KeyTypeSR25519:
		return mpc.SessionTypeSR25519, nil
	default:
		logger.Warn("Unsupported key type", "keyType", keyType)
		return "", fmt.Errorf("unsupported key type: %v", keyType)
	}
}

func composeKeygenIdempotentKey(walletID string, natMsg *nats.Msg) string {
	var uniqueKey string
	sid := natMsg.Header.Get("SessionID")
	if sid != "" {
		uniqueKey = fmt.Sprintf("%s:%s", walletID, sid)
	} else {
		uniqueKey = walletID
	}
	return fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, uniqueKey)
}
