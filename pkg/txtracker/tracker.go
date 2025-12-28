// Package txtracker monitors submitted transactions for block inclusion,
// receipt status, and confirmation finality.
//
// Flow:
//
//	broadcast → mempool → included (block N) → confirming → finalized (block N + target)
//
// It polls JSON-RPC endpoints on a configurable interval, updates the
// Transaction record in the DB, fires webhooks on state changes, and
// handles stuck/dropped tx detection.
package txtracker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/logger"
)

const (
	DefaultPollInterval        = 5 * time.Second
	DefaultStuckTimeout        = 5 * time.Minute
	DefaultTargetConfirmations = 12
	MaxPollAttempts            = 720 // 1 hour at 5s
	ReorgSafetyMargin          = 6   // extra confirmations after finality before stopping
)

// WebhookFunc is called when transaction state changes occur.
type WebhookFunc func(ctx context.Context, orgID, event string, payload interface{})

// RPCClient abstracts JSON-RPC calls for receipt/block queries.
type RPCClient interface {
	GetTransactionReceipt(ctx context.Context, txHash string) (*Receipt, error)
	GetBlockNumber(ctx context.Context) (int64, error)
	// CallForRevertReason replays a failed tx to extract the revert reason.
	CallForRevertReason(ctx context.Context, txHash string) (string, error)
}

// Receipt represents the subset of an EVM transaction receipt we track.
type Receipt struct {
	Status      int    `json:"status"` // 0=reverted, 1=success
	BlockNumber int64  `json:"blockNumber"`
	BlockHash   string `json:"blockHash"`
	GasUsed     string `json:"gasUsed"`
	TxHash      string `json:"txHash"`
}

// trackedTx is internal state for a transaction being monitored.
type trackedTx struct {
	txID      string
	orgID     string
	txHash    string
	startedAt time.Time
	attempts  int
	cancel    context.CancelFunc

	// Reorg detection: last-seen block data for this tx.
	lastBlockHash   string
	lastBlockNumber int64
}

// Tracker monitors broadcast transactions until they reach finality.
type Tracker struct {
	database     *db.Database
	rpcClients   map[string]RPCClient // chain → client
	webhookFn    WebhookFunc
	pollInterval time.Duration
	stuckTimeout time.Duration

	mu      sync.Mutex
	tracked map[string]*trackedTx // txID → tracked
	done    chan struct{}
	wg      sync.WaitGroup
}

// Config configures the tracker.
type Config struct {
	Database     *db.Database
	RPCClients   map[string]RPCClient
	WebhookFn    WebhookFunc
	PollInterval time.Duration
	StuckTimeout time.Duration
}

// New creates a Tracker. Call Track() to start monitoring individual transactions.
func New(cfg Config) *Tracker {
	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = DefaultPollInterval
	}
	stuckTimeout := cfg.StuckTimeout
	if stuckTimeout == 0 {
		stuckTimeout = DefaultStuckTimeout
	}

	return &Tracker{
		database:     cfg.Database,
		rpcClients:   cfg.RPCClients,
		webhookFn:    cfg.WebhookFn,
		pollInterval: pollInterval,
		stuckTimeout: stuckTimeout,
		tracked:      make(map[string]*trackedTx),
		done:         make(chan struct{}),
	}
}

// Track begins monitoring a transaction. Safe for concurrent use.
func (t *Tracker) Track(txID, orgID, txHash, chain string) error {
	rpc, ok := t.rpcClients[chain]
	if !ok {
		return fmt.Errorf("no RPC client configured for chain %q", chain)
	}

	t.mu.Lock()
	if _, exists := t.tracked[txID]; exists {
		t.mu.Unlock()
		return nil // already tracking
	}

	ctx, cancel := context.WithCancel(context.Background())
	tt := &trackedTx{
		txID:      txID,
		orgID:     orgID,
		txHash:    txHash,
		startedAt: time.Now(),
		cancel:    cancel,
	}
	t.tracked[txID] = tt
	t.mu.Unlock()

	// Update the tx status to "broadcast"
	if tx, err := orm.Get[db.Transaction](t.database.ORM, txID); err == nil {
		if tx.Status == "signed" {
			sys := "system"
			tx.RecordTransition("broadcast", "tx submitted to network", &sys)
			hash := txHash
			tx.BroadcastHash = &hash
			now := time.Now()
			tx.BroadcastAt = &now
			if tx.TargetConfirms == 0 {
				tx.TargetConfirms = DefaultTargetConfirmations
			}
			tx.Update()
		}
	}

	t.wg.Add(1)
	go t.poll(ctx, tt, rpc, chain)
	return nil
}

// Stop gracefully shuts down all tracking goroutines.
func (t *Tracker) Stop() {
	close(t.done)
	t.mu.Lock()
	for _, tt := range t.tracked {
		tt.cancel()
	}
	t.mu.Unlock()
	t.wg.Wait()
}

// poll is the per-transaction monitoring loop.
func (t *Tracker) poll(ctx context.Context, tt *trackedTx, rpc RPCClient, chain string) {
	defer t.wg.Done()
	defer func() {
		t.mu.Lock()
		delete(t.tracked, tt.txID)
		t.mu.Unlock()
	}()

	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		case <-ticker.C:
			tt.attempts++

			// Check for stuck tx
			if time.Since(tt.startedAt) > t.stuckTimeout && tt.attempts > 0 {
				tx, err := orm.Get[db.Transaction](t.database.ORM, tt.txID)
				if err != nil {
					continue
				}
				if tx.BlockNumber == nil { // still not included
					sys := "system"
					tx.RecordTransition("stuck", fmt.Sprintf("no receipt after %s", t.stuckTimeout), &sys)
					tx.Update()
					t.fireWebhook(tt.orgID, "tx.stuck", map[string]string{
						"tx_id":   tt.txID,
						"tx_hash": tt.txHash,
						"chain":   chain,
					})
					// Keep polling but with reduced urgency is handled by MaxPollAttempts
				}
			}

			if tt.attempts > MaxPollAttempts {
				logger.Warn("Tx tracker giving up", "txId", tt.txID, "attempts", tt.attempts)
				return
			}

			// Try to get receipt
			receipt, err := rpc.GetTransactionReceipt(ctx, tt.txHash)
			if err != nil || receipt == nil {
				// If we previously saw this tx in a block but now receipt is nil,
				// it was reorged out of the chain.
				if tt.lastBlockHash != "" {
					tx, loadErr := orm.Get[db.Transaction](t.database.ORM, tt.txID)
					if loadErr == nil {
						sys := "system"
						tx.RecordTransition("broadcast",
							fmt.Sprintf("reorg detected: tx was in block %d (%s) but receipt is now nil",
								tt.lastBlockNumber, tt.lastBlockHash), &sys)
						tx.BlockNumber = nil
						tx.BlockHash = nil
						tx.Confirmations = 0
						tx.FinalizedAt = nil
						tx.FinalizationBlock = nil
						tx.Update()
						t.fireWebhook(tt.orgID, "tx.reorged", map[string]string{
							"tx_id":        tt.txID,
							"tx_hash":      tt.txHash,
							"chain":        chain,
							"former_block": fmt.Sprintf("%d", tt.lastBlockNumber),
							"former_hash":  tt.lastBlockHash,
						})
					}
					tt.lastBlockHash = ""
					tt.lastBlockNumber = 0
				}
				continue // not included (yet / anymore)
			}

			// Reorg detection: block hash changed for the same tx
			if tt.lastBlockHash != "" && tt.lastBlockHash != receipt.BlockHash {
				tx, loadErr := orm.Get[db.Transaction](t.database.ORM, tt.txID)
				if loadErr == nil {
					sys := "system"
					tx.RecordTransition("confirming",
						fmt.Sprintf("reorg: tx moved from block %s to %s (block %d→%d)",
							tt.lastBlockHash[:12], receipt.BlockHash[:12],
							tt.lastBlockNumber, receipt.BlockNumber), &sys)
					blockNum := receipt.BlockNumber
					tx.BlockNumber = &blockNum
					blockHash := receipt.BlockHash
					tx.BlockHash = &blockHash
					tx.FinalizedAt = nil
					tx.FinalizationBlock = nil
					tx.Update()
					t.fireWebhook(tt.orgID, "tx.reorged", map[string]string{
						"tx_id":     tt.txID,
						"tx_hash":   tt.txHash,
						"chain":     chain,
						"new_block": fmt.Sprintf("%d", receipt.BlockNumber),
					})
				}
			}
			tt.lastBlockHash = receipt.BlockHash
			tt.lastBlockNumber = receipt.BlockNumber

			// Receipt found — tx is included in a block
			tx, err := orm.Get[db.Transaction](t.database.ORM, tt.txID)
			if err != nil {
				logger.Error("Tx tracker: failed to load tx", err, "txId", tt.txID)
				return
			}

			// Record block inclusion (only once)
			if tx.BlockNumber == nil {
				blockNum := receipt.BlockNumber
				tx.BlockNumber = &blockNum
				blockHash := receipt.BlockHash
				tx.BlockHash = &blockHash
				gasUsed := receipt.GasUsed
				tx.GasUsed = &gasUsed
				status := receipt.Status
				tx.ReceiptStatus = &status

				if status == 0 {
					// Transaction reverted
					reason, _ := rpc.CallForRevertReason(ctx, tt.txHash)
					if reason != "" {
						tx.RevertReason = &reason
					}
					sys := "system"
					tx.RecordTransition("reverted",
						fmt.Sprintf("reverted at block %d: %s", blockNum, reason), &sys)
					tx.Update()
					t.fireWebhook(tt.orgID, "tx.reverted", map[string]string{
						"tx_id":        tt.txID,
						"tx_hash":      tt.txHash,
						"block_number": fmt.Sprintf("%d", blockNum),
						"reason":       reason,
					})
					return // done tracking
				}

				sys := "system"
				tx.RecordTransition("confirming",
					fmt.Sprintf("included in block %d", blockNum), &sys)
				tx.Update()
				t.fireWebhook(tt.orgID, "tx.included", map[string]string{
					"tx_id":        tt.txID,
					"tx_hash":      tt.txHash,
					"block_number": fmt.Sprintf("%d", blockNum),
				})
			}

			// Check confirmations
			currentBlock, err := rpc.GetBlockNumber(ctx)
			if err != nil {
				continue
			}

			confirmations := int(currentBlock - *tx.BlockNumber)
			if confirmations < 0 {
				confirmations = 0
			}
			tx.Confirmations = confirmations

			target := tx.TargetConfirms
			if target == 0 {
				target = DefaultTargetConfirmations
			}

			if confirmations >= target && tx.FinalizedAt == nil {
				now := time.Now()
				tx.FinalizedAt = &now
				tx.FinalizationBlock = &currentBlock
				sys := "system"
				tx.RecordTransition("finalized",
					fmt.Sprintf("reached %d/%d confirmations at block %d",
						confirmations, target, currentBlock), &sys)
				tx.Update()
				t.fireWebhook(tt.orgID, "tx.finalized", map[string]string{
					"tx_id":         tt.txID,
					"tx_hash":       tt.txHash,
					"block_number":  fmt.Sprintf("%d", *tx.BlockNumber),
					"confirmations": fmt.Sprintf("%d", confirmations),
				})
				// Continue polling for ReorgSafetyMargin more blocks to catch late reorgs
				// before declaring tracking complete.
			}

			// After finalization, keep polling for a safety margin to detect late reorgs
			if tx.FinalizedAt != nil && confirmations >= target+ReorgSafetyMargin {
				return // truly done: past finalization + safety margin
			}

			tx.Update()
		}
	}
}

func (t *Tracker) fireWebhook(orgID, event string, payload interface{}) {
	if t.webhookFn != nil {
		t.webhookFn(context.Background(), orgID, event, payload)
	}
}

// TrackedCount returns the number of transactions currently being monitored.
func (t *Tracker) TrackedCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.tracked)
}

// --- Default JSON-RPC client implementation ---

// JSONRPC is a basic EVM JSON-RPC client for receipt and block queries.
type JSONRPC struct {
	URL        string
	HTTPClient *http.Client
}

// NewJSONRPC creates a JSON-RPC client for the given endpoint.
func NewJSONRPC(url string) *JSONRPC {
	return &JSONRPC{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *JSONRPC) call(ctx context.Context, method string, params []interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.URL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func (c *JSONRPC) GetTransactionReceipt(ctx context.Context, txHash string) (*Receipt, error) {
	result, err := c.call(ctx, "eth_getTransactionReceipt", []interface{}{txHash})
	if err != nil {
		return nil, err
	}
	if string(result) == "null" {
		return nil, nil // not yet mined
	}

	var raw struct {
		Status      string `json:"status"`
		BlockNumber string `json:"blockNumber"`
		BlockHash   string `json:"blockHash"`
		GasUsed     string `json:"gasUsed"`
		TxHash      string `json:"transactionHash"`
	}
	if err := json.Unmarshal(result, &raw); err != nil {
		return nil, err
	}

	status := 0
	if raw.Status == "0x1" {
		status = 1
	}

	return &Receipt{
		Status:      status,
		BlockNumber: hexToInt64(raw.BlockNumber),
		BlockHash:   raw.BlockHash,
		GasUsed:     raw.GasUsed,
		TxHash:      raw.TxHash,
	}, nil
}

func (c *JSONRPC) GetBlockNumber(ctx context.Context) (int64, error) {
	result, err := c.call(ctx, "eth_blockNumber", []interface{}{})
	if err != nil {
		return 0, err
	}

	var hex string
	if err := json.Unmarshal(result, &hex); err != nil {
		return 0, err
	}
	return hexToInt64(hex), nil
}

func (c *JSONRPC) CallForRevertReason(ctx context.Context, txHash string) (string, error) {
	// Fetch the original tx to replay it
	result, err := c.call(ctx, "eth_getTransactionByHash", []interface{}{txHash})
	if err != nil {
		return "", err
	}
	if string(result) == "null" {
		return "", nil
	}

	var txData map[string]interface{}
	if err := json.Unmarshal(result, &txData); err != nil {
		return "", err
	}

	callParams := map[string]interface{}{
		"from": txData["from"],
		"to":   txData["to"],
		"data": txData["input"],
	}
	if val, ok := txData["value"]; ok {
		callParams["value"] = val
	}

	blockNum, _ := txData["blockNumber"].(string)
	revertResult, err := c.call(ctx, "eth_call", []interface{}{callParams, blockNum})
	if err != nil {
		// The error message often contains the revert reason
		return err.Error(), nil
	}

	var revertHex string
	if err := json.Unmarshal(revertResult, &revertHex); err == nil && len(revertHex) > 2 {
		return decodeRevertReason(revertHex), nil
	}
	return "", nil
}

// hexToInt64 parses a 0x-prefixed hex string to int64.
func hexToInt64(hex string) int64 {
	hex = strings.TrimPrefix(hex, "0x")
	var n int64
	fmt.Sscanf(hex, "%x", &n)
	return n
}

// decodeRevertReason attempts to extract a human-readable revert string.
// Solidity revert strings are ABI-encoded as Error(string).
func decodeRevertReason(hexData string) string {
	hexData = strings.TrimPrefix(hexData, "0x")
	if len(hexData) < 8 {
		return hexData
	}

	// Error(string) selector: 0x08c379a0
	if hexData[:8] == "08c379a0" && len(hexData) >= 136 {
		// offset at 8..72, length at 72..136, string starts at 136
		var length int64
		fmt.Sscanf(hexData[72:136], "%x", &length)
		if length > 0 && int(136+length*2) <= len(hexData) {
			bytes := make([]byte, length)
			for i := int64(0); i < length; i++ {
				fmt.Sscanf(hexData[136+i*2:138+i*2], "%x", &bytes[i])
			}
			return string(bytes)
		}
	}

	return hexData
}
