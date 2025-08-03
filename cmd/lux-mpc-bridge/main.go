// lux-mpc-bridge provides a compatibility layer for the Lux Bridge to use Lux MPC
package main

import (
	"fmt"
	"os"

	// "github.com/luxfi/mpc/pkg/bridge" // TODO: Implement bridge package
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	app := &cli.App{
		Name:    "lux-mpc-bridge",
		Usage:   "Bridge compatibility server for Lux MPC",
		Version: fmt.Sprintf("%s-%s (%s)", Version, Commit, Date),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "nats-url",
				Usage:   "NATS server URL",
				Value:   "nats://localhost:4222",
				EnvVars: []string{"NATS_URL"},
			},
			&cli.IntFlag{
				Name:    "port",
				Usage:   "Port to listen on (bridge compatibility)",
				Value:   6000,
				EnvVars: []string{"BRIDGE_PORT"},
			},
			&cli.StringFlag{
				Name:    "key-path",
				Usage:   "Path to initiator key file",
				Value:   "",
				EnvVars: []string{"INITIATOR_KEY_PATH"},
			},
		},
		Action: func(c *cli.Context) error {
			return runServer(c, logger)
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Fatal("Failed to run bridge compatibility server", zap.Error(err))
	}
}

func runServer(c *cli.Context, logger *zap.Logger) error {
	natsURL := c.String("nats-url")
	port := c.Int("port")
	keyPath := c.String("key-path")

	logger.Info("Starting Lux MPC bridge compatibility server",
		zap.String("nats-url", natsURL),
		zap.Int("port", port),
		zap.String("version", Version),
	)

	// TODO: Implement bridge compatibility server
	_ = natsURL
	_ = port
	_ = keyPath

	logger.Info("Bridge compatibility server not yet implemented")
	return fmt.Errorf("bridge compatibility server not yet implemented")
}
