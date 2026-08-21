package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// A published test vector: Anvil / Hardhat account #0. Its private key derives a
// fixed account, so "sign a known digest and recover the expected address" is an
// assertion against a value no code in this package produced.
const (
	knownKey  = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	knownAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
)

// TestSignAndRecoverKnownDigest is the core guarantee: a signature the signer
// produces over a 32-byte digest recovers to the exact account the signer
// claims, with no private key handled by the caller after construction.
func TestSignAndRecoverKnownDigest(t *testing.T) {
	signer, err := LocalFromHex(knownKey)
	if err != nil {
		t.Fatalf("LocalFromHex: %v", err)
	}

	want := common.HexToAddress(knownAddr)
	if signer.Account() != want {
		t.Fatalf("account = %s, want %s", signer.Account(), want)
	}

	digest := crypto.Keccak256([]byte("lux mainnet deploy"))
	if len(digest) != 32 {
		t.Fatalf("digest is %d bytes, not 32", len(digest))
	}

	sig, err := signer.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.V != 0 && sig.V != 1 {
		t.Fatalf("recovery id v = %d, want 0 or 1", sig.V)
	}

	got, err := Recover(digest, sig)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != want {
		t.Fatalf("recovered %s, want %s", got, want)
	}
}

// TestAccountFromEveryKeyForm proves the account is a property of the curve, not
// the encoding: the 65-, 64-, and 33-byte forms of one key derive one account.
func TestAccountFromEveryKeyForm(t *testing.T) {
	key, err := crypto.HexToECDSA(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	want := common.HexToAddress(knownAddr)

	uncompressed := crypto.FromECDSAPub(&key.PublicKey) // 65 bytes, 0x04‖X‖Y
	forms := map[string][]byte{
		"uncompressed-65": uncompressed,
		"uncompressed-64": uncompressed[1:],
		"compressed-33":   crypto.CompressPubkey(&key.PublicKey),
	}
	for name, pub := range forms {
		got, err := Account(pub)
		if err != nil {
			t.Fatalf("%s: Account: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s: account = %s, want %s", name, got, want)
		}
	}

	if _, err := Account([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("a 3-byte key derived an account; want an error")
	}
}

// TestRemoteSignsThroughSeam proves the MPC seam: a Remote signer holding only
// its account and a sign function produces a signature that recovers to that
// account. The sign function stands in for a threshold round.
func TestRemoteSignsThroughSeam(t *testing.T) {
	local, err := LocalFromHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}

	// The quorum's job, reduced to its contract: digest in, (r, s, v) out. No
	// account passes through it; the caller already knows the account.
	quorum := func(ctx context.Context, digest []byte) (Signature, error) {
		return local.Sign(ctx, digest)
	}
	remote, err := NewRemote(local.Account(), quorum)
	if err != nil {
		t.Fatal(err)
	}

	digest := crypto.Keccak256([]byte("threshold round"))
	sig, err := remote.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Recover(digest, sig)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != remote.Account() {
		t.Fatalf("recovered %s, want %s", got, remote.Account())
	}
}

// TestSignTxRecoversSender assembles real transactions and checks the sender the
// EVM will recover is the signing account — for a legacy tx and an EIP-1559 tx,
// and for contract creation (no recipient), which is what a deploy is.
func TestSignTxRecoversSender(t *testing.T) {
	signer, err := LocalFromHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(96369) // Lux mainnet
	to := common.HexToAddress("0x00000000000000000000000000000000000000dE")

	cases := map[string]*types.Transaction{
		"legacy-call": types.NewTx(&types.LegacyTx{
			Nonce: 7, GasPrice: big.NewInt(25_000_000_000), Gas: 21000,
			To: &to, Value: big.NewInt(1_000_000_000_000_000_000),
		}),
		"dynamic-call": types.NewTx(&types.DynamicFeeTx{
			ChainID: chainID, Nonce: 7,
			GasTipCap: big.NewInt(1_000_000_000), GasFeeCap: big.NewInt(30_000_000_000), Gas: 21000,
			To: &to, Value: big.NewInt(5),
		}),
		"dynamic-deploy": types.NewTx(&types.DynamicFeeTx{
			ChainID: chainID, Nonce: 8,
			GasTipCap: big.NewInt(1_000_000_000), GasFeeCap: big.NewInt(30_000_000_000), Gas: 500000,
			To: nil, Data: []byte{0x60, 0x80, 0x60, 0x40}, // a contract-creation payload
		}),
	}

	for name, tx := range cases {
		signed, err := SignTx(context.Background(), signer, tx, chainID)
		if err != nil {
			t.Fatalf("%s: SignTx: %v", name, err)
		}
		from, err := types.Sender(types.LatestSignerForChainID(chainID), signed)
		if err != nil {
			t.Fatalf("%s: Sender: %v", name, err)
		}
		if from != signer.Account() {
			t.Fatalf("%s: sender = %s, want %s", name, from, signer.Account())
		}
		if signed.ChainId().Cmp(chainID) != 0 {
			t.Fatalf("%s: chain id = %s, want %s", name, signed.ChainId(), chainID)
		}
	}
}

// TestTwoStepDigestApply proves the split path a deploy uses when the signer is
// out of process: build the digest, sign it elsewhere, apply the result. It must
// land the same transaction the one-call SignTx would.
func TestTwoStepDigestApply(t *testing.T) {
	signer, err := LocalFromHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(96369)
	to := common.HexToAddress("0x00000000000000000000000000000000000000dE")
	tx := types.NewTx(&types.LegacyTx{
		Nonce: 1, GasPrice: big.NewInt(1_000_000_000), Gas: 21000, To: &to, Value: big.NewInt(1),
	})

	digest, err := Digest(tx, chainID)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	sig, err := signer.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed, err := Apply(tx, chainID, sig, signer.Account())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(chainID), signed)
	if err != nil {
		t.Fatalf("Sender: %v", err)
	}
	if from != signer.Account() {
		t.Fatalf("sender = %s, want %s", from, signer.Account())
	}

	// A signature bound to a different account is refused, not broadcast.
	if _, err := Apply(tx, chainID, sig, to); err == nil {
		t.Fatal("Apply accepted a signature for the wrong account")
	}
}

// TestQuorumOverHTTP exercises the production transport against a stub of the MPC
// signing oracle: the request carries only a digest, the response carries
// (r, s, v), and the recovered account is the wallet's. This is everything up to
// the live quorum; the stub is where a real threshold round would run.
func TestQuorumOverHTTP(t *testing.T) {
	oracleKey, err := LocalFromHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mpc/sign" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var in struct {
			Message  string `json:"message"`
			Encoding string `json:"encoding"`
			Network  string `json:"network"`
			WalletID string `json:"walletId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if in.Network != "evm" || in.WalletID != "wallet-1" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		digest, err := hex.DecodeString(in.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sig, err := oracleKey.Sign(r.Context(), digest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"r":         hex.EncodeToString(sig.R[:]),
			"s":         hex.EncodeToString(sig.S[:]),
			"v":         vStr(sig.V),
			"signature": hex.EncodeToString(sig.Bytes()),
		})
	}))
	defer srv.Close()

	remote, err := Quorum{
		Endpoint: srv.URL,
		WalletID: "wallet-1",
		Network:  "evm",
	}.Signer(oracleKey.Account())
	if err != nil {
		t.Fatalf("Quorum.Signer: %v", err)
	}

	digest := crypto.Keccak256([]byte("broadcast me"))
	sig, err := remote.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Recover(digest, sig)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != oracleKey.Account() {
		t.Fatalf("recovered %s, want %s", got, oracleKey.Account())
	}
}

// TestSignatureFromRSVLeftPads guards the one lossy spot: r or s shorter than 32
// bytes (a leading zero dropped by big-endian encoding) must left-pad, or the
// scalar shifts and recovery lands on a different account.
func TestSignatureFromRSVLeftPads(t *testing.T) {
	sig, err := SignatureFromRSV([]byte{0x01}, []byte{0x02}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sig.R[31] != 0x01 || sig.S[31] != 0x02 {
		t.Fatalf("scalars not right-aligned: r=%x s=%x", sig.R, sig.S)
	}
	for i := 0; i < 31; i++ {
		if sig.R[i] != 0 || sig.S[i] != 0 {
			t.Fatalf("scalars not left-padded with zero at %d", i)
		}
	}
	if sig.V != 1 {
		t.Fatalf("v = %d, want 1", sig.V)
	}
}

func vStr(v byte) string {
	return string(rune('0' + v))
}
