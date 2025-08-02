package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/nats-io/nats.go"
)

// handleSigningEventCGGMP21 handles signing events for CGGMP21 protocol
func (ec *eventConsumer) handleSigningEventCGGMP21(msg *types.SignTxMessage, natMsg *nats.Msg) {
	// Check for duplicate session and track if new
	if ec.checkDuplicateSession(msg.WalletID, msg.TxID) {
		duplicateErr := fmt.Errorf("duplicate signing request detected for walletID=%s txID=%s", msg.WalletID, msg.TxID)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			duplicateErr,
			"Duplicate session",
			natMsg,
		)
		return
	}

	// Create CGGMP21 signing session
	session, err := ec.node.CreateSigningSession(
		mpc.SessionTypeECDSA, // CGGMP21 only supports ECDSA
		msg.WalletID,
		msg.TxID,
		msg.NetworkInternalCode,
		ec.signingResultQueue,
	)
	if err != nil {
		// Check if the error is due to node not being in participant list
		if errors.Is(err, mpc.ErrNotInParticipantList) {
			logger.Info("Node is not in participant list for this wallet, skipping signing",
				"walletID", msg.WalletID,
				"txID", msg.TxID,
				"nodeID", ec.node.ID(),
			)
			return // Skip signing instead of treating as error
		}

		logger.Error("Failed to create CGGMP21 signing session", err)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			"Failed to create signing session",
			natMsg,
		)
		return
	}

	// Initialize the session with transaction data
	txBigInt := new(big.Int).SetBytes(msg.Tx)
	err = session.Init(txBigInt)
	if err != nil {
		if errors.Is(err, mpc.ErrNotEnoughParticipants) {
			logger.Info("RETRY LATER: Not enough participants to sign")
			// Return for retry later
			return
		}
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			"Failed to init signing session",
			natMsg,
		)
		return
	}

	// Mark session as already processed
	ec.addSession(msg.WalletID, msg.TxID)

	ctx, done := context.WithCancel(context.Background())
	
	// Monitor for errors
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-session.ErrChan():
				if err != nil {
					ec.handleSigningSessionError(
						msg.WalletID,
						msg.TxID,
						msg.NetworkInternalCode,
						err,
						"Failed to sign tx",
						natMsg,
					)
					return
				}
			}
		}
	}()

	// Start listening to incoming messages
	session.ListenToIncomingMessageAsync()

	// Small delay to ensure all nodes are ready
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

	// Define success callback
	onSuccess := func(data []byte) {
		done()
		ec.sendReplyToRemoveMsg(natMsg)
	}

	// Start the signing process
	go session.Sign(onSuccess)
}