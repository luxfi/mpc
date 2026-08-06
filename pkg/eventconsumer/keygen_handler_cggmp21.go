package eventconsumer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/luxfi/mpc/pkg/logger"
)

// runCGGMP21Keygen runs the CGGMP21 ceremony and returns the wallet's secp256k1
// public key: the key behind its EVM, Bitcoin, LUX and XRPL addresses.
//
// It publishes nothing. Running a ceremony and announcing a wallet are separate
// jobs — a wallet's key set has more than one leg, and only the orchestrator can
// see whether the set as a whole is worth announcing.
func (ec *eventConsumer) runCGGMP21Keygen(ctx context.Context, orgID, walletID string) ([]byte, error) {
	keygenSession, err := ec.node.CreateKeyGenSession(walletID, ec.mpcThreshold, ec.genKeyResultQueue, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to create CGGMP21 key generation session: %w", err)
	}
	keygenSession.Init()

	monitorCtx, done := context.WithCancel(ctx)
	defer done()

	errorChan := make(chan error, 1)
	go func() {
		select {
		case <-monitorCtx.Done():
			return
		case err := <-keygenSession.ErrChan():
			if err != nil {
				logger.Error("CGGMP21 keygen session error", err)
				select {
				case errorChan <- err:
				default:
				}
			}
		}
	}()

	keygenSession.ListenToIncomingMessageAsync()

	// Small delay for peer setup
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

	go keygenSession.ProcessOutboundMessage()

	completionChan := make(chan string, 1)
	go func() {
		completionChan <- keygenSession.WaitForFinish()
	}()

	select {
	case pubKeyHex := <-completionChan:
		if pubKeyHex == "" {
			// The session sends "" for every failure it can detect, including a
			// failed kvstore.Put and a failed keyinfo save. Treating that as
			// success — which this handler used to do — announces a wallet whose
			// EVM and Bitcoin addresses are published while fewer than t+1 nodes
			// actually hold a share, so the addresses can receive funds and can
			// never sign. That is the same shape of loss this change removes on
			// the Solana side, and the same rule applies: under uncertainty,
			// emit nothing.
			return nil, fmt.Errorf("CGGMP21 keygen produced no public key")
		}
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("CGGMP21 keygen returned a malformed public key: %w", err)
		}
		return pubKeyBytes, nil

	case err := <-errorChan:
		return nil, fmt.Errorf("CGGMP21 keygen error: %w", err)

	case <-ctx.Done():
		return nil, fmt.Errorf("keygen session timed out after %v", KeyGenTimeOut)
	}
}
