package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MChainDispatcher anchors batches of audit events to a Lux M-Chain
// audit-anchor RPC endpoint.
//
// Wire protocol: when batchSize events have accumulated, the dispatcher
// POSTs JSON {batchHash, fromSeq, toSeq, prevAnchor, events:[...]} to
// MChainURL. The server is expected to record (batchHash, fromSeq, toSeq)
// on chain and return 200. The dispatcher does NOT itself sign or
// transact — that responsibility belongs to whatever validator set is
// behind the anchor RPC.
//
// On HTTP failure, Append returns the error and does not advance the
// chain. Callers can retry or fail open depending on the operational
// posture (composite mode pairs this with WORM so a transient anchor
// outage does not lose audit data).
type MChainDispatcher struct {
	url       string
	apiKey    string
	batchSize int

	mu     sync.Mutex
	seq    uint64
	head   string
	pend   []*Event
	anchor string // last successful batchHash, used as prevAnchor for the next POST

	httpClient *http.Client
}

// NewMChainDispatcher constructs an anchor dispatcher. batchSize <=0
// defaults to 32. The HTTP client uses a 10s timeout, which is short
// enough that a stuck anchor won't pin a signing thread.
func NewMChainDispatcher(url, apiKey string, batchSize int) (*MChainDispatcher, error) {
	if url == "" {
		return nil, fmt.Errorf("audit/mchain: url is required")
	}
	if batchSize <= 0 {
		batchSize = 32
	}
	return &MChainDispatcher{
		url:       url,
		apiKey:    apiKey,
		batchSize: batchSize,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (d *MChainDispatcher) Append(ctx context.Context, ev *Event) (*Event, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	sealed, err := ev.Seal(d.seq, d.head)
	if err != nil {
		return nil, fmt.Errorf("audit/mchain: seal: %w", err)
	}
	d.seq = sealed.Seq + 1
	d.head = sealed.Hash
	d.pend = append(d.pend, sealed)

	if len(d.pend) >= d.batchSize {
		if err := d.flushLocked(ctx); err != nil {
			// Flush failure: leave events in pending so a later Append
			// (or a manual flush) retries. Return the error so the caller
			// can decide whether to fail the request.
			return sealed, err
		}
	}
	return sealed, nil
}

// Flush forces an out-of-band anchor of any pending events. Useful for
// graceful shutdown.
func (d *MChainDispatcher) Flush(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushLocked(ctx)
}

func (d *MChainDispatcher) flushLocked(ctx context.Context) error {
	if len(d.pend) == 0 {
		return nil
	}
	from := d.pend[0].Seq
	to := d.pend[len(d.pend)-1].Seq

	// batchHash = SHA-256(prevAnchor || hash_of_each_event_in_order).
	h := sha256.New()
	if d.anchor != "" {
		if prev, err := hex.DecodeString(d.anchor); err == nil {
			h.Write(prev)
		}
	}
	for _, ev := range d.pend {
		if b, err := hex.DecodeString(ev.Hash); err == nil {
			h.Write(b)
		}
	}
	batchHash := hex.EncodeToString(h.Sum(nil))

	body, err := json.Marshal(map[string]any{
		"batchHash":  batchHash,
		"fromSeq":    from,
		"toSeq":      to,
		"prevAnchor": d.anchor,
		"events":     d.pend,
	})
	if err != nil {
		return fmt.Errorf("audit/mchain: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("audit/mchain: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if d.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+d.apiKey)
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("audit/mchain: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("audit/mchain: anchor rejected (status=%d)", resp.StatusCode)
	}
	d.anchor = batchHash
	d.pend = d.pend[:0]
	return nil
}

func (d *MChainDispatcher) VerifyHead(_ context.Context) (uint64, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seq == 0 {
		return 0, "", nil
	}
	return d.seq - 1, d.head, nil
}

func (d *MChainDispatcher) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.Flush(ctx)
}
