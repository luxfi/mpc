// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package main, file sign_curve_routing_test.go.
//
// End-to-end tests for curve selection at the daemon's own signing entry point.
//
// They drive ConsensusMPCBackend.TriggerSign — the one function every product
// surface funnels through (HTTP /sign, /v1/mpc/sign, the ZAP servers, the
// transaction pipeline) — and put a REAL threshold ring behind it. The ring
// reads the curve the daemon published on `mpc:sign` and runs THAT curve's
// actual protocol, then publishes the result the daemon is waiting for. The
// signature is finally checked with the verifier its target chain uses:
// crypto/ed25519.Verify for Solana, public-key recovery for the EVM.
//
// The join is the whole point. A test that calls frost.SignEd25519 directly
// proves the library works, and would go on passing while the daemon asked for
// the wrong curve — which is precisely the bug this file exists to catch. The
// complementary seam, "the session uses the right primitive over the right
// share", is pinned in pkg/mpc/ed25519_signing_session_test.go.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/mpc/internal/ceremony"
	mpcapi "github.com/luxfi/mpc/pkg/api"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/luxfi/mpc/pkg/transport"
	"github.com/luxfi/mpc/pkg/types"
)

// --- in-process message bus -------------------------------------------------

// mapKV is the smallest thing satisfying kvstore.KVStore, so the real state
// store and key-info store run against it unchanged.
type mapKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMapKV() *mapKV { return &mapKV{m: map[string][]byte{}} }

func (k *mapKV) Put(key string, value []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = value
	return nil
}

func (k *mapKV) Get(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[key]
	if !ok {
		return nil, errors.New("key not found: " + key)
	}
	return v, nil
}

func (k *mapKV) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, key)
	return nil
}

func (k *mapKV) Close() error  { return nil }
func (k *mapKV) Backup() error { return nil }

var _ kvstore.KVStore = (*mapKV)(nil)

// inprocPubSub is a messaging.PubSub with no broker: handlers are invoked in
// their own goroutine, as NATS would, so the daemon's publish/await handshake
// runs exactly as it does in production.
type inprocPubSub struct {
	mu   sync.Mutex
	subs map[string][]func(*nats.Msg)
}

func newInprocPubSub() *inprocPubSub {
	return &inprocPubSub{subs: map[string][]func(*nats.Msg){}}
}

func (p *inprocPubSub) Publish(topic string, message []byte) error {
	p.mu.Lock()
	handlers := append([]func(*nats.Msg){}, p.subs[topic]...)
	p.mu.Unlock()
	for _, h := range handlers {
		go h(&nats.Msg{Subject: topic, Data: message})
	}
	return nil
}

func (p *inprocPubSub) PublishWithReply(topic, _ string, data []byte, _ map[string]string) error {
	return p.Publish(topic, data)
}

func (p *inprocPubSub) Subscribe(topic string, handler func(*nats.Msg)) (messaging.Subscription, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subs[topic] = append(p.subs[topic], handler)
	return noopSubscription{}, nil
}

type noopSubscription struct{}

func (noopSubscription) Unsubscribe() error { return nil }

var _ messaging.PubSub = (*inprocPubSub)(nil)

// unusedSigner stands in for the node identity. TriggerSign only needs the
// envelope signed; the ring in these tests does not verify the initiator,
// because who asked is a different question from which curve was asked for.
type unusedSigner struct{}

func (unusedSigner) SignMessage(payload []byte) []byte { return nil }

// --- the ring ---------------------------------------------------------------

// keySet is one wallet's material on both curves, produced by real ceremonies.
//
// Generated once per test binary and shared: CGGMP21 keygen runs Paillier key
// generation and is the expensive part of this file by a wide margin, while
// nothing under test depends on the keys being fresh.
type keySet struct {
	parties   []party.ID
	ed25519   map[party.ID]*frost.Config
	secp256k1 map[party.ID]*cmp.Config
}

var (
	sharedKeysOnce sync.Once
	sharedKeys     *keySet
	sharedKeysErr  error
)

func testKeys(t *testing.T) *keySet {
	t.Helper()
	sharedKeysOnce.Do(func() {
		ids := ceremony.Parties()
		ks := &keySet{
			parties:   ids,
			ed25519:   map[party.ID]*frost.Config{},
			secp256k1: map[party.ID]*cmp.Config{},
		}

		edRaw, err := ceremony.Run(ids, []byte("e2e-ed25519-keygen"), func(id party.ID) protocol.StartFunc {
			return frost.KeygenEd25519(id, ids, 1)
		})
		if err != nil {
			sharedKeysErr = err
			return
		}
		for id, res := range edRaw {
			cfg, ok := res.(*frost.Config)
			if !ok {
				sharedKeysErr = errors.New("ed25519 keygen produced the wrong config type")
				return
			}
			ks.ed25519[id] = cfg
		}

		pl := pool.NewPool(0)
		defer pl.TearDown()
		cmpRaw, err := ceremony.Run(ids, []byte("e2e-secp256k1-keygen"), func(id party.ID) protocol.StartFunc {
			return cmp.Keygen(curve.Secp256k1{}, id, ids, 1, pl)
		})
		if err != nil {
			sharedKeysErr = err
			return
		}
		for id, res := range cmpRaw {
			cfg, ok := res.(*cmp.Config)
			if !ok {
				sharedKeysErr = errors.New("secp256k1 keygen produced the wrong config type")
				return
			}
			ks.secp256k1[id] = cfg
		}
		sharedKeys = ks
	})
	if sharedKeysErr != nil {
		t.Fatalf("test key ceremonies failed: %v", sharedKeysErr)
	}
	return sharedKeys
}

// ed25519PubKey is the wallet key as crypto/ed25519.Verify wants it.
func (k *keySet) ed25519PubKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	b, err := k.ed25519[k.parties[0]].PublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal ed25519 public key: %v", err)
	}
	return ed25519.PublicKey(b)
}

// secp256k1PubKey is the wallet key in the compressed encoding public-key
// recovery compares against.
func (k *keySet) secp256k1PubKey(t *testing.T) []byte {
	t.Helper()
	b, err := k.secp256k1[k.parties[0]].PublicPoint().MarshalBinary()
	if err != nil {
		t.Fatalf("marshal secp256k1 public key: %v", err)
	}
	return b
}

// ring stands in for the signing cluster. It subscribes to `mpc:sign`, runs the
// real protocol for the curve the daemon named, and publishes the result event
// on the per-wallet topic the daemon awaits.
//
// It deliberately does NOT decide a curve of its own: it obeys msg.KeyType. If
// the daemon routes a Solana request to secp256k1, this ring dutifully produces
// an ECDSA signature and ed25519.Verify rejects it — which is the failure the
// tests are here to observe.
type ring struct {
	t    *testing.T
	keys *keySet
	bus  *inprocPubSub

	mu       sync.Mutex
	observed []types.SignTxMessage
}

func newRing(t *testing.T, bus *inprocPubSub, keys *keySet) *ring {
	t.Helper()
	r := &ring{t: t, keys: keys, bus: bus}
	if _, err := bus.Subscribe("mpc:sign", r.handle); err != nil {
		t.Fatalf("ring subscribe: %v", err)
	}
	return r
}

// requests returns the sign requests the ring saw, in arrival order.
func (r *ring) requests() []types.SignTxMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]types.SignTxMessage{}, r.observed...)
}

func (r *ring) handle(m *nats.Msg) {
	var msg types.SignTxMessage
	if err := json.Unmarshal(m.Data, &msg); err != nil {
		return
	}
	r.mu.Lock()
	r.observed = append(r.observed, msg)
	r.mu.Unlock()

	topic := event.SigningResultTopicBase + "." + msg.WalletID
	signers := r.keys.parties[:2]

	var result event.SigningResultEvent
	switch msg.KeyType {
	case types.KeyTypeEd25519:
		result = r.signEd25519(msg, signers)
	case types.KeyTypeSecp256k1:
		result = r.signSecp256k1(msg, signers)
	default:
		result = event.SigningResultEvent{
			ResultType:  event.ResultTypeError,
			WalletID:    msg.WalletID,
			TxID:        msg.TxID,
			ErrorReason: "ring: unsupported key type " + string(msg.KeyType),
		}
	}

	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	_ = r.bus.Publish(topic, data)
}

// signEd25519 mirrors frostSigningSession: PureEdDSA over the message itself
// (never a digest of it), published in the Signature field as RFC 8032 R‖S.
func (r *ring) signEd25519(msg types.SignTxMessage, signers []party.ID) event.SigningResultEvent {
	fail := func(reason string) event.SigningResultEvent {
		return event.SigningResultEvent{
			ResultType: event.ResultTypeError, WalletID: msg.WalletID, TxID: msg.TxID,
			ErrorReason: reason,
		}
	}
	raw, err := ceremony.Run(signers, []byte(msg.TxID), func(id party.ID) protocol.StartFunc {
		return frost.SignEd25519(r.keys.ed25519[id], signers, msg.Tx)
	})
	if err != nil {
		return fail("ed25519 ceremony: " + err.Error())
	}
	sig, ok := raw[signers[0]].(frost.Ed25519Signature)
	if !ok {
		return fail("ed25519 ceremony produced the wrong signature type")
	}
	encoded, err := sig.MarshalBinary()
	if err != nil {
		return fail("encode ed25519 signature: " + err.Error())
	}
	return event.SigningResultEvent{
		ResultType: event.ResultTypeSuccess,
		WalletID:   msg.WalletID,
		TxID:       msg.TxID,
		Signature:  encoded,
	}
}

// signSecp256k1 mirrors cggmp21SigningSession: ECDSA over a 32-byte digest,
// published as R/S plus the recovery id.
func (r *ring) signSecp256k1(msg types.SignTxMessage, signers []party.ID) event.SigningResultEvent {
	fail := func(reason string) event.SigningResultEvent {
		return event.SigningResultEvent{
			ResultType: event.ResultTypeError, WalletID: msg.WalletID, TxID: msg.TxID,
			ErrorReason: reason,
		}
	}
	pl := pool.NewPool(0)
	defer pl.TearDown()

	raw, err := ceremony.Run(signers, []byte(msg.TxID), func(id party.ID) protocol.StartFunc {
		return cmp.Sign(r.keys.secp256k1[id], signers, msg.Tx, pl)
	})
	if err != nil {
		return fail("secp256k1 ceremony: " + err.Error())
	}
	type ethSigner interface{ SigEthereum() ([]byte, error) }
	sig, ok := raw[signers[0]].(ethSigner)
	if !ok {
		return fail("secp256k1 ceremony produced the wrong signature type")
	}
	ethSig, err := sig.SigEthereum()
	if err != nil {
		return fail("encode ethereum signature: " + err.Error())
	}
	return event.SigningResultEvent{
		ResultType:        event.ResultTypeSuccess,
		WalletID:          msg.WalletID,
		TxID:              msg.TxID,
		R:                 ethSig[:32],
		S:                 ethSig[32:64],
		SignatureRecovery: []byte{ethSig[64]},
	}
}

// --- rig --------------------------------------------------------------------

const testWalletID = "wallet-e2e"

// newBackend builds the real ConsensusMPCBackend over an in-process bus and a
// real (single-node) key-info store, and registers the wallet's key set exactly
// as TriggerKeygen does. ecdsaKey/eddsaKey may be empty to model a wallet whose
// keygen leg for that curve never completed.
func newBackend(t *testing.T, bus *inprocPubSub, ecdsaKey, eddsaKey string) *ConsensusMPCBackend {
	t.Helper()
	store := transport.NewKeyInfoStore(transport.NewStateStore(newMapKV(), nil, "node-a"), "node-a")
	if err := store.RegisterKey(testWalletID, 2, ecdsaKey, eddsaKey, nil); err != nil {
		t.Fatalf("register wallet key set: %v", err)
	}
	return &ConsensusMPCBackend{
		pubSub:       bus,
		keyInfoStore: store,
		identity:     unusedSigner{},
		nodeID:       "node-a",
		threshold:    2,
	}
}

// --- tests ------------------------------------------------------------------

// TestSolanaRequestProducesAnEd25519SignatureTheChainAccepts is the headline
// case: a Solana signature requested through the daemon's signing entry point
// must come back as something crypto/ed25519.Verify accepts under the wallet's
// own Ed25519 key.
//
// The message is deliberately not 32 bytes. Solana signs the serialized
// transaction message, and PureEdDSA hashes it inside the challenge, so any
// pre-hashing or length clamp on the way in would sign a digest of a digest and
// produce a signature the chain rejects.
func TestSolanaRequestProducesAnEd25519SignatureTheChainAccepts(t *testing.T) {
	keys := testKeys(t)
	bus := newInprocPubSub()
	r := newRing(t, bus, keys)
	backend := newBackend(t, bus,
		hex.EncodeToString(keys.secp256k1PubKey(t)),
		hex.EncodeToString(keys.ed25519PubKey(t)))

	message := []byte("a serialized solana transaction message of no particular length")

	res, err := backend.TriggerSign("org-1", testWalletID, types.NetworkSOL, message)
	if err != nil {
		t.Fatalf("TriggerSign for SOL: %v", err)
	}

	reqs := r.requests()
	if len(reqs) != 1 {
		t.Fatalf("ring saw %d sign requests, want 1", len(reqs))
	}
	if reqs[0].KeyType != types.KeyTypeEd25519 {
		t.Fatalf("SOL routed to key type %q, want %q", reqs[0].KeyType, types.KeyTypeEd25519)
	}
	if string(reqs[0].Tx) != string(message) {
		t.Fatalf("the ring was asked to sign %q, want the caller's message %q", reqs[0].Tx, message)
	}

	sig, err := hex.DecodeString(res.Signature)
	if err != nil {
		t.Fatalf("signature is not hex: %v (%q)", err, res.Signature)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(keys.ed25519PubKey(t), message, sig) {
		t.Fatal("crypto/ed25519.Verify rejected the signature the product path produced")
	}
}

// TestTONRequestAlsoRoutesToEd25519 confirms the routing is a property of the
// table and not of one hard-coded chain.
func TestTONRequestAlsoRoutesToEd25519(t *testing.T) {
	keys := testKeys(t)
	bus := newInprocPubSub()
	r := newRing(t, bus, keys)
	backend := newBackend(t, bus,
		hex.EncodeToString(keys.secp256k1PubKey(t)),
		hex.EncodeToString(keys.ed25519PubKey(t)))

	message := []byte("ton cell payload")
	res, err := backend.TriggerSign("org-1", testWalletID, types.NetworkTON, message)
	if err != nil {
		t.Fatalf("TriggerSign for TON: %v", err)
	}
	if got := r.requests()[0].KeyType; got != types.KeyTypeEd25519 {
		t.Fatalf("TON routed to key type %q, want %q", got, types.KeyTypeEd25519)
	}
	sig, err := hex.DecodeString(res.Signature)
	if err != nil {
		t.Fatalf("signature is not hex: %v", err)
	}
	if !ed25519.Verify(keys.ed25519PubKey(t), message, sig) {
		t.Fatal("crypto/ed25519.Verify rejected the TON signature")
	}
}

// TestEVMRequestStillRoutesToSecp256k1AndVerifies is the no-regression guard
// for the higher-value leg. The signature must still recover to the wallet's
// own secp256k1 key — the property an EVM chain checks when it derives the
// sender from a signature.
func TestEVMRequestStillRoutesToSecp256k1AndVerifies(t *testing.T) {
	keys := testKeys(t)
	pub := keys.secp256k1PubKey(t)

	for _, network := range []types.NetworkCode{types.NetworkETH, types.NetworkEVM, types.NetworkBTC, types.NetworkLUX} {
		t.Run(string(network), func(t *testing.T) {
			bus := newInprocPubSub()
			r := newRing(t, bus, keys)
			backend := newBackend(t, bus, hex.EncodeToString(pub), hex.EncodeToString(keys.ed25519PubKey(t)))

			digest := make([]byte, 32)
			for i := range digest {
				digest[i] = byte(i + 1)
			}

			res, err := backend.TriggerSign("org-1", testWalletID, network, digest)
			if err != nil {
				t.Fatalf("TriggerSign for %s: %v", network, err)
			}
			if got := r.requests()[0].KeyType; got != types.KeyTypeSecp256k1 {
				t.Fatalf("%s routed to key type %q, want %q", network, got, types.KeyTypeSecp256k1)
			}

			rb, err := hex.DecodeString(res.R)
			if err != nil {
				t.Fatalf("R is not hex: %v", err)
			}
			sb, err := hex.DecodeString(res.S)
			if err != nil {
				t.Fatalf("S is not hex: %v", err)
			}
			// Recovery succeeds only when (r,s,v) recovers to THIS wallet's
			// public key, which is exactly what an EVM chain checks.
			if _, err := mpc.CalculateRecoveryByte(rb, sb, digest, pub); err != nil {
				t.Fatalf("%s signature does not recover to the wallet key: %v", network, err)
			}
			// And it must not be mistaken for an Ed25519 signature.
			if ed25519.Verify(keys.ed25519PubKey(t), digest, append(rb, sb...)) {
				t.Fatal("an ECDSA signature verified as Ed25519 — the curves are not separated")
			}
		})
	}
}

// TestUnknownNetworkIsRefusedNotDefaulted is the guard against the failure the
// whole design exists to prevent. An unrecognised network must reach no signing
// machinery at all — not the ring, not a curve, not a default.
func TestUnknownNetworkIsRefusedNotDefaulted(t *testing.T) {
	keys := testKeys(t)
	for _, network := range []types.NetworkCode{"", "UNKNOWN", "SOLANA", "APTOS", "secp256k1", "ed25519"} {
		t.Run(string(network), func(t *testing.T) {
			bus := newInprocPubSub()
			r := newRing(t, bus, keys)
			backend := newBackend(t, bus,
				hex.EncodeToString(keys.secp256k1PubKey(t)),
				hex.EncodeToString(keys.ed25519PubKey(t)))

			res, err := backend.TriggerSign("org-1", testWalletID, network, []byte("payload"))
			if err == nil {
				t.Fatalf("network %q was signed for (result %+v), want a refusal", network, res)
			}
			if !errors.Is(err, types.ErrUnknownNetwork) {
				t.Fatalf("network %q refused with %v, want ErrUnknownNetwork", network, err)
			}
			if got := r.requests(); len(got) != 0 {
				t.Fatalf("a refused request still reached the ring as %+v", got)
			}
		})
	}
}

// TestWalletWithoutAnEd25519KeyRefusesSolana covers the state the keygen design
// deliberately allows: the Ed25519 leg may fail without failing the wallet, so a
// wallet can hold a secp256k1 key and no Ed25519 key. Asking it for a Solana
// signature must be refused, not served from the key it does have.
func TestWalletWithoutAnEd25519KeyRefusesSolana(t *testing.T) {
	keys := testKeys(t)
	bus := newInprocPubSub()
	r := newRing(t, bus, keys)
	backend := newBackend(t, bus, hex.EncodeToString(keys.secp256k1PubKey(t)), "")

	_, err := backend.TriggerSign("org-1", testWalletID, types.NetworkSOL, []byte("solana message"))
	if err == nil {
		t.Fatal("a wallet with no Ed25519 key signed a Solana request")
	}
	if !strings.Contains(err.Error(), "no ed25519 key") {
		t.Fatalf("refusal was %v, want it to name the missing Ed25519 key", err)
	}
	if got := r.requests(); len(got) != 0 {
		t.Fatalf("a refused request still reached the ring as %+v", got)
	}

	// The same wallet still signs for the EVM: the refusal is per-curve, not a
	// wallet-wide outage.
	digest := make([]byte, 32)
	if _, err := backend.TriggerSign("org-1", testWalletID, types.NetworkETH, digest); err != nil {
		t.Fatalf("the secp256k1 leg must be unaffected: %v", err)
	}
}

// TestWalletRecordedBeforeKeySetsStillSigns is the guard for the upgrade path.
//
// Every wallet minted before key sets were recorded has a metadata record with
// no public keys in it. That record denies nothing — it simply predates the
// field — so reading its silence as "this wallet has no Ed25519 key" would
// refuse every wallet in existence at the moment this change ships. Both curves
// must still route, with the missing share left as the thing that fails closed.
func TestWalletRecordedBeforeKeySetsStillSigns(t *testing.T) {
	keys := testKeys(t)
	bus := newInprocPubSub()
	r := newRing(t, bus, keys)
	backend := newBackend(t, bus, "", "") // the pre-existing record: threshold only

	message := []byte("a solana transaction from a wallet minted before this change")
	res, err := backend.TriggerSign("org-1", testWalletID, types.NetworkSOL, message)
	if err != nil {
		t.Fatalf("a wallet recorded before key sets must still sign: %v", err)
	}
	if got := r.requests()[0].KeyType; got != types.KeyTypeEd25519 {
		t.Fatalf("SOL routed to %q, want ed25519", got)
	}
	sig, err := hex.DecodeString(res.Signature)
	if err != nil {
		t.Fatalf("signature is not hex: %v", err)
	}
	if !ed25519.Verify(keys.ed25519PubKey(t), message, sig) {
		t.Fatal("crypto/ed25519.Verify rejected the signature")
	}

	if _, err := backend.TriggerSign("org-1", testWalletID, types.NetworkETH, make([]byte, 32)); err != nil {
		t.Fatalf("the secp256k1 leg must be unaffected too: %v", err)
	}
}

// TestSignRequestCarriesTheNetwork pins the network onto the wire envelope. It
// is signed over by the initiator (SignTxMessage.Raw includes it), so a peer can
// see which network a request claimed rather than inferring it from the curve.
func TestSignRequestCarriesTheNetwork(t *testing.T) {
	keys := testKeys(t)
	bus := newInprocPubSub()
	r := newRing(t, bus, keys)
	backend := newBackend(t, bus,
		hex.EncodeToString(keys.secp256k1PubKey(t)),
		hex.EncodeToString(keys.ed25519PubKey(t)))

	if _, err := backend.TriggerSign("org-1", testWalletID, types.NetworkSOLDevnet, []byte("msg")); err != nil {
		t.Fatalf("TriggerSign: %v", err)
	}
	got := r.requests()[0]
	if got.NetworkInternalCode != string(types.NetworkSOLDevnet) {
		t.Fatalf("network on the wire = %q, want %q", got.NetworkInternalCode, types.NetworkSOLDevnet)
	}
	if got.KeyType != types.KeyTypeEd25519 {
		t.Fatalf("SOL-devnet routed to %q, want ed25519", got.KeyType)
	}
}

// --- /sign boundary ---------------------------------------------------------

// TestDecodeSignPayloadIsCurveShaped pins the payload rule to the scheme rather
// than to the endpoint. The 32-byte clamp is correct for ECDSA and wrong for
// PureEdDSA, where the bytes signed are the message.
func TestDecodeSignPayloadIsCurveShaped(t *testing.T) {
	long := strings.Repeat("ab", 300) // 300 bytes, a plausible Solana message

	// Ed25519: any non-empty length, carried through untouched.
	for _, in := range []string{long, "00", strings.Repeat("cd", 32)} {
		got, err := decodeSignPayload(types.NetworkSOL, in)
		if err != nil {
			t.Fatalf("ed25519 payload of %d hex chars rejected: %v", len(in), err)
		}
		want, _ := hex.DecodeString(in)
		if string(got) != string(want) {
			t.Fatal("the payload was altered on the way in")
		}
	}

	// secp256k1: exactly 32 bytes, because it signs a digest.
	if _, err := decodeSignPayload(types.NetworkETH, long); err == nil {
		t.Fatal("secp256k1 accepted a 300-byte payload; it signs a 32-byte digest")
	}
	if _, err := decodeSignPayload(types.NetworkETH, strings.Repeat("cd", 32)); err != nil {
		t.Fatalf("secp256k1 rejected a 32-byte digest: %v", err)
	}

	// Empty is refused for both — signing nothing is never intended.
	for _, network := range []types.NetworkCode{types.NetworkSOL, types.NetworkETH} {
		if _, err := decodeSignPayload(network, ""); err == nil {
			t.Fatalf("%s accepted an empty payload", network)
		}
	}

	// An unknown network never yields bytes to sign.
	if _, err := decodeSignPayload("APTOS", strings.Repeat("cd", 32)); !errors.Is(err, types.ErrUnknownNetwork) {
		t.Fatalf("unknown network: got %v, want ErrUnknownNetwork", err)
	}
}

// TestIdempotencyKeyIsBoundToTheNetwork proves the same bytes requested for two
// networks cannot share a cached signature. They are signatures from different
// keys, so reusing one for the other would return a signature for a chain that
// never asked for it.
func TestIdempotencyKeyIsBoundToTheNetwork(t *testing.T) {
	c := newSignIdempotencyCache()
	signer := func(_, _ string, _ types.NetworkCode, _ []byte) (*mpcapi.SignResult, error) {
		return &mpcapi.SignResult{Signature: "aabb"}, nil
	}
	eth := signFields{OrgID: "org-1", WalletID: testWalletID, Network: "ETH", PayloadHash: "deadbeef"}
	sol := signFields{OrgID: "org-1", WalletID: testWalletID, Network: "SOL", PayloadHash: "deadbeef"}

	if _, err := c.Do("idem-1", eth, types.NetworkETH, []byte{0xde}, signer); err != nil {
		t.Fatalf("first sign: %v", err)
	}
	if _, err := c.Do("idem-1", sol, types.NetworkSOL, []byte{0xde}, signer); !errors.Is(err, errIdempotencyConflict) {
		t.Fatalf("same key across networks: got %v, want a conflict", err)
	}
}
