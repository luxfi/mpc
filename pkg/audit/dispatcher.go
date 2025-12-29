package audit

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Dispatcher is the only surface mpcd uses to record audit events.
//
// Append must be safe for concurrent callers and must be linearizable:
// the Seq returned for a given event is the position assigned in the
// chain stored at that target. Implementations MUST refuse to assign a
// non-monotonic Seq.
//
// VerifyHead returns the Hash of the latest event (or "" for an empty
// chain) along with its Seq. Callers compare across replicas to detect
// fork or tampering.
//
// Close flushes any pending writes and releases handles.
type Dispatcher interface {
	Append(ctx context.Context, ev *Event) (*Event, error)
	VerifyHead(ctx context.Context) (seq uint64, hash string, err error)
	Close() error
}

// Mode names accepted by NewDispatcher. The string literals are the
// values passed via the --audit-store flag and so are part of the
// operator-facing surface; do not rename without coordinating with
// the runbook.
const (
	StoreLocalWORM      = "local-worm"
	StoreMChain         = "mchain"
	StoreS3GlacierVault = "s3-glacier-vault"
	StoreAzureImmutable = "azure-immutable"
	StoreGCSObjectLock  = "gcs-object-lock"
)

// Config is the union of every backend's configuration. Only fields
// relevant to the selected store need to be populated; NewDispatcher
// fails loudly on missing values for the chosen target.
type Config struct {
	Store string

	// LocalWORM
	WORMPath string

	// MChain (RPC anchor: nodes POST batch-roots to this URL)
	MChainURL    string
	MChainAPIKey string
	MChainBatch  int // events per anchor batch (>=1)

	// Composite — comma-separated list of stores; Append fails if any leg fails.
	// Used for redundancy (e.g. "local-worm,mchain"). Read via the first leg.
	Composite []string
}

// NewDispatcher constructs the dispatcher named by cfg.Store. Composite
// mode is selected by passing Store="composite" with cfg.Composite
// listing the legs in priority order.
//
// Cloud-backed dispatchers (S3 Glacier Vault, Azure Immutable, GCS Object
// Lock) currently return ErrNotImplemented. They are wired into the flag
// surface so operators can plan for them, but the SDK paths are gated
// behind separate build tags so the default binary remains small. Use
// the local-worm + mchain composite for production today; flip to a
// cloud target only after the corresponding terraform module has been
// applied AND the relevant build tag enabled.
func NewDispatcher(ctx context.Context, cfg Config) (Dispatcher, error) {
	switch cfg.Store {
	case "", StoreLocalWORM:
		if cfg.WORMPath == "" {
			return nil, fmt.Errorf("audit: local-worm requires WORMPath")
		}
		return NewWORMDispatcher(cfg.WORMPath)
	case StoreMChain:
		if cfg.MChainURL == "" {
			return nil, fmt.Errorf("audit: mchain requires MChainURL")
		}
		return NewMChainDispatcher(cfg.MChainURL, cfg.MChainAPIKey, cfg.MChainBatch)
	case StoreS3GlacierVault, StoreAzureImmutable, StoreGCSObjectLock:
		return nil, fmt.Errorf("audit: %s dispatcher requires the cloud-audit build tag (set --audit-store=local-worm or composite for now)", cfg.Store)
	case "composite":
		legs := make([]Dispatcher, 0, len(cfg.Composite))
		for _, name := range cfg.Composite {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			leg, err := NewDispatcher(ctx, Config{
				Store:        name,
				WORMPath:     cfg.WORMPath,
				MChainURL:    cfg.MChainURL,
				MChainAPIKey: cfg.MChainAPIKey,
				MChainBatch:  cfg.MChainBatch,
			})
			if err != nil {
				for _, l := range legs {
					_ = l.Close()
				}
				return nil, fmt.Errorf("audit: composite leg %q: %w", name, err)
			}
			legs = append(legs, leg)
		}
		if len(legs) == 0 {
			return nil, fmt.Errorf("audit: composite requires at least one leg")
		}
		return &compositeDispatcher{legs: legs}, nil
	default:
		return nil, fmt.Errorf("audit: unknown store %q", cfg.Store)
	}
}

// compositeDispatcher fans Append out to every leg and fails if any leg
// fails. Read operations consult the first leg only — operators verify
// cross-leg consistency out-of-band by comparing VerifyHead values.
type compositeDispatcher struct {
	legs []Dispatcher
	mu   sync.Mutex
}

func (c *compositeDispatcher) Append(ctx context.Context, ev *Event) (*Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var sealed *Event
	for i, leg := range c.legs {
		// Each leg seals its own copy. They will all assign different Seq
		// values (each leg keeps its own chain), but the payloads are
		// identical. Cross-leg consistency is checked out-of-band by
		// comparing event payloads at the same Seq.
		copyEv := &Event{
			Timestamp: ev.Timestamp,
			NodeID:    ev.NodeID,
			Kind:      ev.Kind,
			OrgID:     ev.OrgID,
			WalletID:  ev.WalletID,
			Payload:   ev.Payload,
		}
		out, err := leg.Append(ctx, copyEv)
		if err != nil {
			return nil, fmt.Errorf("audit: composite leg %d: %w", i, err)
		}
		if i == 0 {
			sealed = out
		}
	}
	return sealed, nil
}

func (c *compositeDispatcher) VerifyHead(ctx context.Context) (uint64, string, error) {
	if len(c.legs) == 0 {
		return 0, "", nil
	}
	return c.legs[0].VerifyHead(ctx)
}

func (c *compositeDispatcher) Close() error {
	var firstErr error
	for _, leg := range c.legs {
		if err := leg.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
