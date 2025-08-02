package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// BenchmarkE2EKeyGeneration benchmarks end-to-end key generation
func BenchmarkE2EKeyGeneration(b *testing.B) {
	suite := NewE2ETestSuite(".")
	logger.Init("dev", false) // Disable debug logs for benchmarks

	// Setup infrastructure once
	suite.setupInfrastructure(b)
	defer suite.Cleanup(b)

	// Wait for infrastructure
	time.Sleep(5 * time.Second)

	// Setup and start nodes once
	suite.setupTestIdentities(b)
	suite.setupConsul(b, true)
	suite.startNodes(b)

	// Connect to NATS once
	nc, err := suite.connectToNATS()
	require.NoError(b, err)
	defer nc.Close()

	keyTypes := []types.KeyType{types.KeyTypeECDSA, types.KeyTypeEd25519}

	for _, keyType := range keyTypes {
		b.Run(string(keyType), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sessionID := uuid.NewString()
				walletID := fmt.Sprintf("bench-wallet-%s-%d", keyType, i)

				// Publish key generation request
				keygenRequest := event.KeygenRequest{
					SessionID: sessionID,
					WalletID:  walletID,
					KeyType:   keyType,
				}

				err := nc.Publish(event.KeygenRequestTopic, keygenRequest)
				require.NoError(b, err)

				// Wait for completion
				select {
				case <-suite.waitForKeygenSuccess(b, nc, sessionID):
					// Success
				case <-time.After(2 * time.Minute):
					b.Fatalf("Key generation timeout for session %s", sessionID)
				}
			}
		})
	}
}

// BenchmarkE2ESigning benchmarks end-to-end signing operations
func BenchmarkE2ESigning(b *testing.B) {
	suite := NewE2ETestSuite(".")
	logger.Init("dev", false)

	// Setup infrastructure
	suite.setupInfrastructure(b)
	defer suite.Cleanup(b)

	time.Sleep(5 * time.Second)

	suite.setupTestIdentities(b)
	suite.setupConsul(b, true)
	suite.startNodes(b)

	nc, err := suite.connectToNATS()
	require.NoError(b, err)
	defer nc.Close()

	// Generate keys first
	sessionID := uuid.NewString()
	walletID := "bench-signing-wallet"

	keygenRequest := event.KeygenRequest{
		SessionID: sessionID,
		WalletID:  walletID,
		KeyType:   types.KeyTypeECDSA,
	}

	err = nc.Publish(event.KeygenRequestTopic, keygenRequest)
	require.NoError(b, err)

	select {
	case <-suite.waitForKeygenSuccess(b, nc, sessionID):
		// Key generated successfully
	case <-time.After(2 * time.Minute):
		b.Fatal("Key generation timeout")
	}

	// Benchmark signing
	messageHash := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := uuid.NewString()

		signingRequest := event.SigningRequest{
			SessionID:   sessionID,
			WalletID:    walletID,
			MessageHash: messageHash,
			KeyType:     types.KeyTypeECDSA,
		}

		err := nc.Publish(event.SigningRequestTopic, signingRequest)
		require.NoError(b, err)

		// Wait for signature
		select {
		case <-suite.waitForSigningResult(b, nc, sessionID):
			// Success
		case <-time.After(30 * time.Second):
			b.Fatalf("Signing timeout for session %s", sessionID)
		}
	}
}

// BenchmarkE2EConcurrentSigning benchmarks concurrent signing operations
func BenchmarkE2EConcurrentSigning(b *testing.B) {
	suite := NewE2ETestSuite(".")
	logger.Init("dev", false)

	// Setup infrastructure
	suite.setupInfrastructure(b)
	defer suite.Cleanup(b)

	time.Sleep(5 * time.Second)

	suite.setupTestIdentities(b)
	suite.setupConsul(b, true)
	suite.startNodes(b)

	nc, err := suite.connectToNATS()
	require.NoError(b, err)
	defer nc.Close()

	// Generate multiple keys for concurrent signing
	numWallets := 5
	walletIDs := make([]string, numWallets)

	for i := 0; i < numWallets; i++ {
		sessionID := uuid.NewString()
		walletID := fmt.Sprintf("bench-concurrent-wallet-%d", i)
		walletIDs[i] = walletID

		keygenRequest := event.KeygenRequest{
			SessionID: sessionID,
			WalletID:  walletID,
			KeyType:   types.KeyTypeECDSA,
		}

		err = nc.Publish(event.KeygenRequestTopic, keygenRequest)
		require.NoError(b, err)

		select {
		case <-suite.waitForKeygenSuccess(b, nc, sessionID):
			// Key generated successfully
		case <-time.After(2 * time.Minute):
			b.Fatalf("Key generation timeout for wallet %s", walletID)
		}
	}

	messageHash := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	// Benchmark concurrent signing
	b.ResetTimer()
	b.SetParallelism(numWallets)
	b.RunParallel(func(pb *testing.PB) {
		walletIdx := 0
		for pb.Next() {
			sessionID := uuid.NewString()
			walletID := walletIDs[walletIdx%numWallets]
			walletIdx++

			signingRequest := event.SigningRequest{
				SessionID:   sessionID,
				WalletID:    walletID,
				MessageHash: messageHash,
				KeyType:     types.KeyTypeECDSA,
			}

			err := nc.Publish(event.SigningRequestTopic, signingRequest)
			require.NoError(b, err)

			select {
			case <-suite.waitForSigningResult(b, nc, sessionID):
				// Success
			case <-time.After(30 * time.Second):
				b.Fatalf("Signing timeout for session %s", sessionID)
			}
		}
	})
}

// BenchmarkE2EMessageThroughput benchmarks message throughput
func BenchmarkE2EMessageThroughput(b *testing.B) {
	suite := NewE2ETestSuite(".")
	logger.Init("dev", false)

	// Setup infrastructure
	suite.setupInfrastructure(b)
	defer suite.Cleanup(b)

	time.Sleep(5 * time.Second)

	nc, err := suite.connectToNATS()
	require.NoError(b, err)
	defer nc.Close()

	// Create test message
	testMsg := types.TssMessage{
		WireMsg:        make([]byte, 1024), // 1KB message
		SessionID:      "bench-session",
		Sender:         "bench-sender",
		SequenceNumber: 1,
		KeyType:        types.KeyTypeECDSA,
	}

	b.ResetTimer()
	b.SetBytes(1024) // Message size in bytes

	for i := 0; i < b.N; i++ {
		testMsg.SequenceNumber = uint32(i)
		data, err := testMsg.Marshal()
		require.NoError(b, err)

		err = nc.Publish("bench.topic", data)
		require.NoError(b, err)
	}

	// Ensure all messages are flushed
	err = nc.Flush()
	require.NoError(b, err)
}