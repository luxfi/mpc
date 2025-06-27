package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

func main() {
	const environment = "development"
	numWallets := flag.Int("n", 1, "Number of wallets to generate")
	flag.Parse()

	config.InitViperConfig()
	logger.Init(environment, false)

	natsURL := viper.GetString("nats.url")
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain()
	defer natsConn.Close()

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		KeyPath:  "./event_initiator.key",
	})

	var walletStartTimes sync.Map
	var wg sync.WaitGroup
	var completedCount int32

	startAll := time.Now()

	wg.Add(*numWallets)

	err = mpcClient.OnWalletCreationResult(func(event mpc.KeygenSuccessEvent) {
		startTimeAny, ok := walletStartTimes.Load(event.WalletID)
		if ok {
			startTime := startTimeAny.(time.Time)
			duration := time.Since(startTime).Seconds()
			logger.Info("Wallet created", "walletID", event.WalletID, "duration_seconds", fmt.Sprintf("%.3f", duration))
			walletStartTimes.Delete(event.WalletID)
		} else {
			logger.Warn("Received wallet result but no start time found", "walletID", event.WalletID)
		}
		atomic.AddInt32(&completedCount, 1)
		wg.Done()
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to wallet-creation results", err)
	}

	for i := 0; i < *numWallets; i++ {
		walletID := uuid.New().String()
		walletStartTimes.Store(walletID, time.Now())

		if err := mpcClient.CreateWallet(walletID); err != nil {
			logger.Error("CreateWallet failed", err)
			walletStartTimes.Delete(walletID)
			wg.Done()
			continue
		}
		logger.Info("CreateWallet sent, awaiting result...", "walletID", walletID)
	}

	// Wait until all wallet creations complete
	go func() {
		wg.Wait()
		totalDuration := time.Since(startAll).Seconds()
		logger.Info("All wallets generated", "count", completedCount, "total_duration_seconds", fmt.Sprintf("%.3f", totalDuration))
		os.Exit(0)
	}()

	// Block on SIGINT/SIGTERM (Ctrl+C etc.)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
