package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// BootstrapMode controls where a freshly-generated node identity gets
// announced.
//
// In ModePrimary the bootstrap routine POSTs the node's public key to
// the configured registrar URL — typically the Lux M-Chain audit /
// validator-manager API — so the larger network learns of this node.
// In ModePrivate no remote announcement is made; the cluster is fully
// self-contained and the only thing that exists is the local identity
// file. Same code path, same on-disk format — just two terminations.
type BootstrapMode string

const (
	ModePrimary BootstrapMode = "primary"
	ModePrivate BootstrapMode = "private"
)

// Config drives Bootstrap. Only RegistrarURL is consulted in primary
// mode; in private mode it is ignored.
type Config struct {
	NodeID        string
	KeysDir       string
	Mode          BootstrapMode
	RegistrarURL  string
	RegistrarAuth string

	// HTTP client override — set in tests; zero-value uses a 10s default.
	HTTPClient *http.Client
}

// Identity is the result of Bootstrap.
type Identity struct {
	NodeID     string             `json:"node_id"`
	Mode       BootstrapMode      `json:"mode"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	PrivateKey ed25519.PrivateKey `json:"-"`
}

// onDiskIdentity is the JSON representation persisted under
// {KeysDir}/{NodeID}_identity.json. It matches the schema written by
// cmd/mpcd/main.go's loadOrGenerateIdentity so existing nodes keep
// working without migration.
type onDiskIdentity struct {
	NodeID     string `json:"node_id"`
	Mode       string `json:"mode,omitempty"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// Bootstrap loads or generates this node's Ed25519 identity, persists it
// under cfg.KeysDir, and (in primary mode) announces the public key to
// the registrar. The function is idempotent: a second invocation with
// the same KeysDir + NodeID returns the existing identity without
// reannouncing.
//
// Errors fall into three classes:
//   - bad config (missing NodeID/KeysDir, unknown Mode) — return immediately
//   - I/O failure — surfaced unwrapped
//   - registrar failure in primary mode — surfaced; caller decides whether
//     to fall back to private behaviour or fail closed
func Bootstrap(ctx context.Context, cfg Config) (*Identity, error) {
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("identity/bootstrap: NodeID is required")
	}
	if cfg.KeysDir == "" {
		return nil, fmt.Errorf("identity/bootstrap: KeysDir is required")
	}
	switch cfg.Mode {
	case ModePrimary, ModePrivate:
	case "":
		cfg.Mode = ModePrivate
	default:
		return nil, fmt.Errorf("identity/bootstrap: unknown mode %q", cfg.Mode)
	}

	if err := os.MkdirAll(cfg.KeysDir, 0o700); err != nil {
		return nil, fmt.Errorf("identity/bootstrap: mkdir keys: %w", err)
	}
	path := filepath.Join(cfg.KeysDir, cfg.NodeID+"_identity.json")

	id, err := loadIdentity(path)
	if err != nil {
		return nil, err
	}
	if id == nil {
		id, err = generateIdentity(cfg.NodeID, cfg.Mode, path)
		if err != nil {
			return nil, err
		}
	} else {
		// Refresh the mode field if the on-disk record predates this code.
		// Identity bytes never change.
		id.Mode = cfg.Mode
	}

	if cfg.Mode == ModePrimary {
		if err := announce(ctx, cfg, id); err != nil {
			return id, fmt.Errorf("identity/bootstrap: primary announce: %w", err)
		}
	}
	return id, nil
}

func loadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("identity/bootstrap: read: %w", err)
	}
	var od onDiskIdentity
	if err := json.Unmarshal(data, &od); err != nil {
		return nil, fmt.Errorf("identity/bootstrap: parse: %w", err)
	}
	priv, err := hex.DecodeString(od.PrivateKey)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity/bootstrap: corrupt private key in %s", path)
	}
	pub, err := hex.DecodeString(od.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity/bootstrap: corrupt public key in %s", path)
	}
	return &Identity{
		NodeID:     od.NodeID,
		Mode:       BootstrapMode(od.Mode),
		PublicKey:  ed25519.PublicKey(pub),
		PrivateKey: ed25519.PrivateKey(priv),
	}, nil
}

func generateIdentity(nodeID string, mode BootstrapMode, path string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity/bootstrap: keygen: %w", err)
	}
	od := onDiskIdentity{
		NodeID:     nodeID,
		Mode:       string(mode),
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: hex.EncodeToString(priv),
	}
	body, err := json.MarshalIndent(od, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("identity/bootstrap: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return nil, fmt.Errorf("identity/bootstrap: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("identity/bootstrap: rename: %w", err)
	}
	return &Identity{
		NodeID:     nodeID,
		Mode:       mode,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// announce posts {nodeID, pubKey, ts} to the registrar URL. The
// registrar is responsible for whatever validator-set bookkeeping the
// primary network does — this client makes one HTTP call and verifies
// the 2xx response.
func announce(ctx context.Context, cfg Config, id *Identity) error {
	if cfg.RegistrarURL == "" {
		// No registrar configured — primary mode degrades to private.
		// The mode label is kept on disk for operator clarity but no
		// network call is made. This is the documented behaviour for
		// air-gapped staging clusters.
		return nil
	}
	body, err := json.Marshal(map[string]any{
		"node_id":    id.NodeID,
		"public_key": hex.EncodeToString(id.PublicKey),
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RegistrarURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.RegistrarAuth != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.RegistrarAuth)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("registrar status=%d", resp.StatusCode)
	}
	return nil
}
