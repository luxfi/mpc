// lux-mpc-bridge provides a compatibility layer for the Lux Bridge to use Lux MPC
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/luxfi/mpc/pkg/bridge"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func main() {
	logger := logger.NewLogger("lux-mpc-bridge")

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

	// Create compatibility server
	server, err := bridge.NewCompatibilityServer(natsURL, port, keyPath)
	if err != nil {
		return fmt.Errorf("failed to create compatibility server: %w", err)
	}
	defer server.Close()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errChan <- err
		}
	}()

	select {
	case <-sigChan:
		logger.Info("Received shutdown signal")
		return nil
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}
}