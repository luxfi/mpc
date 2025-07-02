package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

func main() {
	const environment = "dev"
	config.InitViperConfig()
	logger.Init(environment, true)

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

	resharingMsg := &types.ResharingMessage{
		WalletID:     "98f6a23c-e78c-445e-92d9-95ccf927ca35",
		NodeIDs:      []string{"0ce02715-0ead-48ef-9772-2583316cc860", "ac37e85f-caca-4bee-8a3a-49a0fe35abff"}, // new peer IDs
		NewThreshold: 1,                                                                                        // t+1 <= len(NodeIDs)
		KeyType:      types.KeyTypeSecp256k1,
	}
	err = mpcClient.Resharing(resharingMsg)
	if err != nil {
		logger.Fatal("Resharing failed", err)
	}
	fmt.Printf("Resharing(%q) sent, awaiting result...\n", resharingMsg.WalletID)

	// 3) Listen for signing results
	err = mpcClient.OnResharingResult(func(evt event.ResharingResultEvent) {
		logger.Info("Resharing result received",
			"walletID", evt.WalletID,
			"pubKey", fmt.Sprintf("%x", evt.PubKey),
			"newThreshold", evt.NewThreshold,
			"keyType", evt.KeyType,
		)
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to OnResharingResult", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
