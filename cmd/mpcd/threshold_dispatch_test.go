// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Verifies the embedded threshold dispatcher (luxfi/threshold/pkg/thresholdd)
// is reachable from mpcd's process and answers a full keygen → sign → verify
// round-trip with at least one production scheme (BLS — fast keygen, no
// upstream flakiness).
//
// This is the smallest possible test that proves the consolidation is
// real: mpcd embeds the same package the standalone thresholdd CLI uses,
// the wire shape matches what teleport/mpc/src/signers/rpc.ts speaks,
// and the dispatcher refuses unknown schemes with -32601.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

// rpcCall posts a JSON-RPC 2.0 request against the embedded dispatcher
// and unmarshals the result envelope. Mirrors the wire used by the
// teleport mpc bus (signers/rpc.ts).
func rpcCall(t *testing.T, url, method string, params any) (json.RawMessage, *struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env.Result, env.Error
}

// TestEmbeddedDispatcher_BLSRoundTrip verifies the dispatcher mpcd
// embeds answers a real BLS keygen → sign → verify round-trip on the
// same wire teleport's PulsarSigner/CoronaSigner/Cggmp21Signer use.
func TestEmbeddedDispatcher_BLSRoundTrip(t *testing.T) {
	srv, err := thresholdd.NewServer()
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// keygen
	res, rpcErr := rpcCall(t, ts.URL, "bls.keygen", map[string]any{
		"threshold":    2,
		"participants": 3,
	})
	if rpcErr != nil {
		t.Fatalf("bls.keygen error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	var kg struct {
		PublicKey string   `json:"publicKey"`
		Shares    []string `json:"shares"`
	}
	if err := json.Unmarshal(res, &kg); err != nil {
		t.Fatalf("unmarshal keygen: %v", err)
	}
	if kg.PublicKey == "" {
		t.Fatalf("empty publicKey")
	}
	if len(kg.Shares) != 3 {
		t.Fatalf("shares=%d want=3", len(kg.Shares))
	}

	// sign
	msg := hex.EncodeToString([]byte("mpcd embedded dispatch smoke test"))
	res, rpcErr = rpcCall(t, ts.URL, "bls.sign", map[string]any{
		"messageHex": msg,
		"pubKeyHex":  kg.PublicKey,
	})
	if rpcErr != nil {
		t.Fatalf("bls.sign error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	var sg struct {
		SignatureHex string `json:"signatureHex"`
	}
	if err := json.Unmarshal(res, &sg); err != nil {
		t.Fatalf("unmarshal sign: %v", err)
	}
	if sg.SignatureHex == "" {
		t.Fatalf("empty signatureHex")
	}

	// verify
	res, rpcErr = rpcCall(t, ts.URL, "bls.verify", map[string]any{
		"messageHex":   msg,
		"signatureHex": sg.SignatureHex,
		"pubKeyHex":    kg.PublicKey,
	})
	if rpcErr != nil {
		t.Fatalf("bls.verify error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	var vr struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(res, &vr); err != nil {
		t.Fatalf("unmarshal verify: %v", err)
	}
	if !vr.OK {
		t.Fatalf("verify: round-trip signature failed under embedded dispatcher")
	}

	// forgery rejection — different message under same signature must fail
	wrong := hex.EncodeToString([]byte("forged"))
	res, rpcErr = rpcCall(t, ts.URL, "bls.verify", map[string]any{
		"messageHex":   wrong,
		"signatureHex": sg.SignatureHex,
		"pubKeyHex":    kg.PublicKey,
	})
	if rpcErr != nil {
		t.Fatalf("bls.verify(wrong) error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	_ = json.Unmarshal(res, &vr)
	if vr.OK {
		t.Fatalf("verify: forgery accepted (different message)")
	}
}

// TestEmbeddedDispatcher_UnknownScheme verifies the dispatcher returns
// a JSON-RPC -32601 method-not-found for an unrecognized scheme — the
// teleport bus relies on this contract to route fall-back signers.
func TestEmbeddedDispatcher_UnknownScheme(t *testing.T) {
	srv, err := thresholdd.NewServer()
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	_, rpcErr := rpcCall(t, ts.URL, "bogus.keygen", map[string]any{
		"threshold":    1,
		"participants": 1,
	})
	if rpcErr == nil {
		t.Fatalf("expected JSON-RPC error for bogus.keygen, got success")
	}
	if rpcErr.Code != -32601 {
		t.Fatalf("expected -32601 method-not-found, got code=%d msg=%q", rpcErr.Code, rpcErr.Message)
	}
}
