package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/luxfi/geth/common"
)

// Quorum describes how to reach the MPC signing oracle over HTTP. It is the
// mainnet-deploy custody path: the account is a wallet whose key lives only as
// shares across the quorum, and Endpoint is the MPC API that runs a threshold
// signing round on demand.
//
// The endpoint is the existing authenticated signing oracle (POST
// {Endpoint}/v1/mpc/sign). Token authenticates the caller; Session is the
// signing session the oracle binds the request to; Network selects the
// secp256k1 curve ("evm" for any EVM chain). The private key is never present
// here or on the wire — only a digest goes out and (r, s, v) comes back.
type Quorum struct {
	Endpoint string        // base URL, e.g. https://kms.hanzo.ai
	Token    string        // bearer token for the signing oracle
	Session  string        // signing session id the oracle enforces
	WalletID string        // MPC wallet holding the account's key shares
	Network  string        // curve selector; "evm" for EVM chains
	Client   *http.Client  // optional; a 60s client is used when nil
	Timeout  time.Duration // optional per-request timeout override
}

// Signer binds a wallet's known account to its quorum and returns an EVM Signer
// whose Sign runs a threshold round over the MPC oracle. account comes from the
// wallet's keygen result (its evm_address); nothing here reconstructs a key.
func (q Quorum) Signer(account common.Address) (*Remote, error) {
	if strings.TrimSpace(q.Endpoint) == "" {
		return nil, fmt.Errorf("evm: quorum endpoint is required")
	}
	if strings.TrimSpace(q.WalletID) == "" {
		return nil, fmt.Errorf("evm: quorum wallet id is required")
	}
	network := q.Network
	if network == "" {
		network = "evm"
	}
	client := q.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	url := strings.TrimRight(q.Endpoint, "/") + "/v1/mpc/sign"

	return NewRemote(account, func(ctx context.Context, digest []byte) (Signature, error) {
		if q.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, q.Timeout)
			defer cancel()
		}
		body, _ := json.Marshal(map[string]string{
			"message":   hex.EncodeToString(digest),
			"encoding":  "hex",
			"network":   network,
			"walletId":  q.WalletID,
			"sessionId": q.Session,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return Signature{}, fmt.Errorf("evm: build sign request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if q.Token != "" {
			req.Header.Set("Authorization", "Bearer "+q.Token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return Signature{}, fmt.Errorf("evm: reach signing oracle: %w", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if resp.StatusCode != http.StatusOK {
			return Signature{}, fmt.Errorf("evm: signing oracle returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		return parseOracleResult(raw)
	})
}

// parseOracleResult reads an MPC sign response into a Signature. The oracle
// returns the parts as hex (r, s) plus the recovery id v; when only the packed
// 65-byte signature is present it is split instead. Either way the result is the
// same value.
func parseOracleResult(raw []byte) (Signature, error) {
	var out struct {
		Signature string `json:"signature"`
		R         string `json:"r"`
		S         string `json:"s"`
		V         string `json:"v"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Signature{}, fmt.Errorf("evm: signing oracle response is not JSON: %w", err)
	}
	if out.R != "" && out.S != "" && out.V != "" {
		r, err := hex.DecodeString(trim0x(out.R))
		if err != nil {
			return Signature{}, fmt.Errorf("evm: oracle r: %w", err)
		}
		s, err := hex.DecodeString(trim0x(out.S))
		if err != nil {
			return Signature{}, fmt.Errorf("evm: oracle s: %w", err)
		}
		v, err := strconv.Atoi(strings.TrimSpace(out.V))
		if err != nil {
			return Signature{}, fmt.Errorf("evm: oracle v: %w", err)
		}
		return SignatureFromRSV(r, s, byte(v))
	}
	if out.Signature != "" {
		packed, err := hex.DecodeString(trim0x(out.Signature))
		if err != nil {
			return Signature{}, fmt.Errorf("evm: oracle signature: %w", err)
		}
		return ParseSignature(packed)
	}
	return Signature{}, fmt.Errorf("evm: signing oracle returned neither (r, s, v) nor a packed signature")
}
