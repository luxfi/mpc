package eventconsumer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/nats-io/nats.go"
)

// handleKeyGenEventCGGMP21 handles key generation events for CGGMP21 protocol
func (ec *eventConsumer) handleKeyGenEventCGGMP21(msg *event.Message, natMsg *nats.Msg) {
	// Mark session as active
	ec.trackSession(msg.WalletID, "")

	// Remove session from active list when done
	defer ec.untrackSession(msg.WalletID, "")

	// Create a context with timeout for the entire key generation process
	baseCtx, cancel := context.WithTimeout(context.Background(), KeyGenTimeOut)
	defer cancel()

	// Decode the message
	if msg.EventType != MPCGenerateEvent {
		logger.Error("unexpected event type", nil, "expected", MPCGenerateEvent, "got", msg.EventType)
		return
	}

	walletID := msg.WalletID

	// Create CGGMP21 keygen session
	keygenSession, err := ec.node.CreateKeyGenSession(walletID, ec.mpcThreshold, ec.genKeyResultQueue)
	if err != nil {
		ec.handleKeygenSessionError(walletID, err, "Failed to create CGGMP21 key generation session", natMsg)
		return
	}
	keygenSession.Init()

	// Setup context for monitoring
	ctx, done := context.WithCancel(baseCtx)

	// Prepare success event
	successEvent := &event.KeygenResultEvent{
		WalletID:   walletID,
		ResultType: event.ResultTypeSuccess,
	}

	// Channel to communicate errors
	errorChan := make(chan error, 1)

	// Monitor for errors in background
	go func() {
		select {
		case <-ctx.Done():
			return
		case err := <-keygenSession.ErrChan():
			if err != nil {
				logger.Error("CGGMP21 keygen session error", err)
				errorChan <- err
				done()
			}
		}
	}()

	// Start listening to messages
	keygenSession.ListenToIncomingMessageAsync()

	// Small delay for peer setup
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

	// Start processing outbound messages
	go keygenSession.ProcessOutboundMessage()

	// Wait for the keygen to complete
	completionChan := make(chan string, 1)
	go func() {
		result := keygenSession.WaitForFinish()
		completionChan <- result
	}()

	// Wait for completion, error, or timeout
	select {
	case pubKeyHex := <-completionChan:
		// Success - set the public key
		if pubKeyHex != "" {
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err == nil {
				successEvent.ECDSAPubKey = pubKeyBytes
			}
		}
		done() // Signal completion

	case err := <-errorChan:
		// Error occurred
		ec.handleKeygenSessionError(walletID, err, "CGGMP21 keygen error", natMsg)
		return

	case <-baseCtx.Done():
		// Timeout occurred
		logger.Warn("Key generation timed out", "walletID", walletID, "timeout", KeyGenTimeOut)
		ec.handleKeygenSessionError(walletID, fmt.Errorf("keygen session timed out after %v", KeyGenTimeOut), "Key generation timed out", natMsg)
		return
	}

	// Marshal and publish success event
	payload, err := json.Marshal(successEvent)
	if err != nil {
		logger.Error("Failed to marshal keygen success event", err)
		ec.handleKeygenSessionError(walletID, err, "Failed to marshal keygen success event", natMsg)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, walletID)
	if err := ec.genKeyResultQueue.Enqueue(
		key,
		payload,
		&messaging.EnqueueOptions{IdempotententKey: composeKeygenIdempotentKey(walletID, natMsg)},
	); err != nil {
		logger.Error("Failed to publish key generation success message", err)
		ec.handleKeygenSessionError(walletID, err, "Failed to publish key generation success message", natMsg)
		return
	}

	ec.sendReplyToRemoveMsg(natMsg)
	logger.Info("[COMPLETED KEY GEN] CGGMP21 key generation completed successfully", "walletID", walletID)
}