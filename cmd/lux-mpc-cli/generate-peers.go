package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/urfave/cli/v3"
)

const (
	peersFileName = "peers.json"
)

func generatePeers(ctx context.Context, c *cli.Command) error {
	numNodes := c.Int("number")
	if numNodes < 1 {
		return fmt.Errorf("number of nodes must be at least 1")
	}

	outputPath := c.String("output")

	// Check if file already exists
	if _, err := os.Stat(outputPath); err == nil {
		return fmt.Errorf("file %s already exists, won't overwrite", outputPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking file status: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Generate peers data
	peers := make(map[string]string)
	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("node%d", i)
		id, err := uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("failed to generate UUID: %w", err)
		}
		peers[nodeName] = id.String()
	}

	// Convert to JSON
	peersJSON, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, peersJSON, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Successfully generated peers file at %s with %d nodes\n", outputPath, numNodes)
	return nil
}
