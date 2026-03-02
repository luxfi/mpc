package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
)

func main() {
	logger.Init("production", false)
	nodeName := flag.String("name", "", "Provide node name")
	password := flag.String("password", "", "ZapDB encryption password")
	flag.Parse()
	if *nodeName == "" {
		logger.Fatal("Node name is required", nil)
	}
	if *password == "" {
		logger.Fatal("ZapDB password is required", nil)
	}

	dbPath := fmt.Sprintf("./db/%s", *nodeName)

	config := kvstore.Config{
		NodeID:    *nodeName,
		Key:       []byte(*password),
		BackupKey: []byte(*password),
		Dir:       "./backups",
		Path:      dbPath,
	}

	store, err := kvstore.New(config)
	if err != nil {
		logger.Fatal("Failed to create zapdb store", err)
	}
	defer store.Close()

	keys, err := store.Keys()
	if err != nil {
		logger.Fatal("Failed to get keys from zapdb store", err)
	}

	migrated := 0
	for _, key := range keys {
		if strings.HasPrefix(key, "eddsa:") || strings.HasPrefix(key, "ecdsa:") {
			continue
		}
		value, err := store.Get(key)
		if err != nil {
			logger.Fatal(fmt.Sprintf("Failed to get key %q", key), err)
		}
		newKey := fmt.Sprintf("ecdsa:%s", key)
		if err := store.Put(newKey, value); err != nil {
			logger.Fatal(fmt.Sprintf("Failed to write migrated key %q", newKey), err)
		}
		if err := store.Delete(key); err != nil {
			logger.Fatal(fmt.Sprintf("Failed to delete old key %q", key), err)
		}
		migrated++
		fmt.Printf("migrated: %s → %s\n", key, newKey)
	}

	fmt.Printf("Migration complete. %d keys migrated.\n", migrated)

	keys, err = store.Keys()
	if err != nil {
		logger.Fatal("Failed to get keys", err)
	}
	for _, key := range keys {
		fmt.Printf("key = %+v\n", key)
	}
}
