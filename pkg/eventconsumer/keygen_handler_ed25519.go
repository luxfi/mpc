package eventconsumer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/luxfi/mpc/pkg/address"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/logger"
)

// runEd25519Keygen runs FROST distributed key generation over edwards25519 and
// returns the wallet's 32-byte Ed25519 public key.
//
// This is the only function in the daemon permitted to produce that key. The key
// it returns is what becomes a Solana address, so its provenance is the whole
// security property: FROST over secp256k1 (KeygenTaproot) also yields 32 bytes,
// and those 32 bytes base58-encode into an address that looks perfect, accepts
// deposits, and can never be spent from. The ceremony is pinned to
// frost.KeygenEd25519 inside the session, and the result is checked against the
// curve here before it is allowed out.
//
// It returns an error rather than a key whenever anything is uncertain. The
// caller is expected to publish a wallet with no eddsa_pub_key in that case,
// which is the system correctly declining to name an address it cannot sign for.
//
// The shape mirrors runCGGMP21Keygen: run the ceremony, return the key, publish
// nothing. Whether the wallet as a whole succeeded is the orchestrator's call.
func (ec *eventConsumer) runEd25519Keygen(ctx context.Context, orgID, walletID string) ([]byte, error) {
	session, err := ec.node.CreateEdDSAKeyGenSession(walletID, ec.mpcThreshold, ec.genKeyResultQueue, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ed25519 keygen session: %w", err)
	}
	session.Init()

	monitorCtx, done := context.WithCancel(ctx)
	defer done()

	errorChan := make(chan error, 1)
	go func() {
		select {
		case <-monitorCtx.Done():
			return
		case err := <-session.ErrChan():
			if err != nil {
				select {
				case errorChan <- err:
				default:
				}
			}
		}
	}()

	session.ListenToIncomingMessageAsync()

	// Small delay for peer setup, matching the CGGMP21 leg.
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

	go session.ProcessOutboundMessage()

	completionChan := make(chan string, 1)
	go func() {
		completionChan <- session.WaitForFinish()
	}()

	select {
	case pubKeyHex := <-completionChan:
		// The session sends "" for every failure it can detect, so an empty
		// string is a failed ceremony, not an empty key.
		if pubKeyHex == "" {
			return nil, fmt.Errorf("Ed25519 keygen produced no public key")
		}
		pubKey, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("Ed25519 keygen returned malformed public key: %w", err)
		}
		// Last gate before these bytes can become an address: they must decode
		// as a prime-order edwards25519 point. Provenance above is the real
		// defence; this catches a truncated, corrupted, or wrong-curve key.
		if err := address.RequireEd25519(pubKey); err != nil {
			return nil, fmt.Errorf("Ed25519 keygen returned a key that is not on the curve: %w", err)
		}
		return pubKey, nil

	case err := <-errorChan:
		return nil, fmt.Errorf("Ed25519 keygen error: %w", err)

	case <-ctx.Done():
		return nil, fmt.Errorf("Ed25519 keygen timed out after %v", KeyGenTimeOut)
	}
}

// logEd25519LegSkipped records that a wallet was minted without a Solana
// address, so the absence is visible in logs rather than inferred from a missing
// JSON field.
func logEd25519LegSkipped(walletID string, err error) {
	logger.Warn("Ed25519 keygen leg failed; wallet has no Solana address",
		"walletID", walletID,
		"error", err.Error(),
		"consequence", "eddsa_pub_key and sol_address will be absent from the keygen result",
	)
}

// assertKeygenResultConsistent is a belt-and-braces check run immediately before
// the wallet's result is published: if an EdDSA key is present at all, it must be
// a real Ed25519 key. It exists so that any future path that learns to populate
// EDDSAPubKey inherits the curve check without having to remember it.
func assertKeygenResultConsistent(result *event.KeygenResultEvent) error {
	if len(result.EDDSAPubKey) == 0 {
		return nil
	}
	return address.RequireEd25519(result.EDDSAPubKey)
}
