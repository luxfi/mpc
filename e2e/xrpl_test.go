package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestXRPLSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping XRPL signing test in short mode")
	}

	suite := SetupE2ETestSuite(t)
	defer suite.Teardown()

	// Create a wallet first
	walletID := fmt.Sprintf("xrpl-wallet-%s", uuid.New().String())
	keygenResult := createWallet(t, suite, walletID)
	assert.NotNil(t, keygenResult)

	// Test XRPL transaction signing
	t.Run("XRPL_MainnetSigning", func(t *testing.T) {
		testXRPLSigning(t, suite, walletID, types.NetworkXRPL)
	})

	t.Run("XRPL_TestnetSigning", func(t *testing.T) {
		testXRPLSigning(t, suite, walletID, types.NetworkXRPLTestnet)
	})
}

func testXRPLSigning(t *testing.T, suite *E2ETestSuite, walletID string, network types.NetworkCode) {
	t.Logf("Testing XRPL signing for wallet %s on network %s", walletID, network)

	// Example XRPL transaction hash (in real scenario, this would be a properly formatted XRPL transaction)
	// XRPL transactions are typically JSON objects that get serialized and hashed
	xrplTxData := []byte("XRPL_TRANSACTION_DATA_TO_SIGN")
	txID := fmt.Sprintf("xrpl-tx-%s", uuid.New().String())

	// Create signing request
	signingMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  xrplTxData,
		KeyType:             types.KeyTypeSecp256k1, // XRPL uses secp256k1
		NetworkInternalCode: string(network),
	}

	// Sign the message
	msg, err := signingMsg.GetMessage()
	assert.NoError(t, err)

	signature, err := suite.client.PrivKey.Sign(msg)
	assert.NoError(t, err)

	signingMsg.Signature = signature

	// Setup listener for signing result
	signingResult := make(chan *event.SigningResultEvent, 1)
	err = suite.client.OnSignResult(func(event event.SigningResultEvent) {
		if event.TxID == txID {
			signingResult <- &event
		}
	})
	assert.NoError(t, err)

	// Send signing request
	err = suite.client.SignTransaction(signingMsg)
	assert.NoError(t, err)

	// Wait for result
	select {
	case result := <-signingResult:
		assert.NotNil(t, result)
		assert.Equal(t, event.ResultTypeSuccess, result.ResultType)
		assert.Equal(t, walletID, result.WalletID)
		assert.Equal(t, txID, result.TxID)
		assert.Equal(t, string(network), result.NetworkInternalCode)
		
		// For XRPL, we expect a DER-encoded ECDSA signature
		assert.NotEmpty(t, result.Signature)
		t.Logf("XRPL signing successful on %s. Signature length: %d", network, len(result.Signature))
		
		// Verify the signature format (should be DER-encoded for XRPL)
		// In a real implementation, you would verify this is a valid DER-encoded signature
		assert.True(t, len(result.Signature) >= 64, "XRPL signature should be at least 64 bytes")
		
	case <-time.After(30 * time.Second):
		t.Fatal("Timeout waiting for XRPL signing result")
	}
}

func TestXRPLKeyTypeValidation(t *testing.T) {
	// Test that XRPL networks use the correct key type
	assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkXRPL))
	assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkXRPLTestnet))
	assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkXRPLDevnet))
}