// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Tests for the ceremony's node-agreement logic: the common reference seed and
// the position assignment, which every node must compute the same way from
// local information, and the binding of a claimed position to its sender.

package mpc

import (
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/multiparty"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/tfhe"
)

var ceremonyNoise = []byte("lux-mpc-tfhe-session-test-noise-seed-v1")

// TestTFHECRSSeed_KnownAnswer pins the ceremony's common reference seed.
func TestTFHECRSSeed_KnownAnswer(t *testing.T) {
	ids := []party.ID{"node-a", "node-b", "node-c"}
	const want = "cf972f3e60fd2cee2b1faf52bb4a0d1d55e7835c29e753b3cca70c708769909f"
	got := hex.EncodeToString(tfheCRSSeed("wallet-1", ids))
	if got != want {
		t.Errorf("tfheCRSSeed = %s, want %s", got, want)
	}
}

// TestTFHECRSSeed_PermutationInvariant checks the seed is independent of the
// order peers were discovered in.
func TestTFHECRSSeed_PermutationInvariant(t *testing.T) {
	discovered := [][]party.ID{
		{"node-a", "node-b", "node-c"},
		{"node-c", "node-a", "node-b"},
		{"node-b", "node-c", "node-a"},
	}
	var first string
	for i, ids := range discovered {
		ordered, _ := tfhePositions(ids)
		seed := hex.EncodeToString(tfheCRSSeed("wallet-1", ordered))
		if i == 0 {
			first = seed
			continue
		}
		if seed != first {
			t.Fatalf("discovery order %v derived seed %s, want %s", ids, seed, first)
		}
	}
}

// TestTFHECRSSeed_BoundToWalletAndCommittee checks the seed is not reused
// across wallets or committees.
func TestTFHECRSSeed_BoundToWalletAndCommittee(t *testing.T) {
	base := []party.ID{"node-a", "node-b", "node-c"}
	seed := hex.EncodeToString(tfheCRSSeed("wallet-1", base))

	if other := hex.EncodeToString(tfheCRSSeed("wallet-2", base)); other == seed {
		t.Error("two wallets derived the same reference seed")
	}
	if other := hex.EncodeToString(tfheCRSSeed("wallet-1", append(base, "node-d"))); other == seed {
		t.Error("two committees derived the same reference seed")
	}
	// The separator makes the committee list unambiguous: "ab","c" and
	// "a","bc" must not collide.
	split := hex.EncodeToString(tfheCRSSeed("w", []party.ID{"ab", "c"}))
	if other := hex.EncodeToString(tfheCRSSeed("w", []party.ID{"a", "bc"})); other == split {
		t.Error("committee members are concatenated ambiguously")
	}
}

// TestTFHEPositions_Canonical checks positions are 1-based, dense, and
// independent of arrival order.
func TestTFHEPositions_Canonical(t *testing.T) {
	ordered, at := tfhePositions([]party.ID{"node-c", "node-a", "node-b"})
	want := []party.ID{"node-a", "node-b", "node-c"}
	if !reflect.DeepEqual(ordered, want) {
		t.Fatalf("order = %v, want %v", ordered, want)
	}
	for i, id := range want {
		if at[id] != i+1 {
			t.Errorf("%s at position %d, want %d", id, at[id], i+1)
		}
	}
	if _, ok := at["node-z"]; ok {
		t.Error("a non-member was assigned a position")
	}
}

// TestTFHECeremony_NodesAgreeOnCollectiveKey runs both rounds on three
// separate members and checks they assemble a byte-identical collective public
// key whose shares threshold-decrypt. Each member holds only its own
// contribution.
func TestTFHECeremony_NodesAgreeOnCollectiveKey(t *testing.T) {
	params, lit, err := tfheParams()
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	const (
		walletID  = "wallet-ceremony"
		threshold = 2
		total     = 3
	)
	ordered, at := tfhePositions([]party.ID{"node-c", "node-a", "node-b"})
	seed := tfheCRSSeed(walletID, ordered)

	// Each node derives the reference polynomial and samples its own
	// contribution.
	type node struct {
		position int
		crp      multiparty.PublicKeyGenCRP
		ckg      multiparty.PublicKeyGenProtocol
		dealer   *tfhe.Party
	}
	nodes := make([]*node, total)
	for _, id := range ordered {
		position := at[id]
		crp, ckg, err := tfhe.Reference(params, seed)
		if err != nil {
			t.Fatalf("reference polynomial at position %d: %v", position, err)
		}
		dealer, err := tfhe.NewParty(position, threshold, total, params)
		if err != nil {
			t.Fatalf("member at position %d: %v", position, err)
		}
		nodes[position-1] = &node{position: position, crp: crp, ckg: ckg, dealer: dealer}
	}

	// Round 1, over the wire encodings the session uses.
	public := make([]tfhe.Public, 0, total)
	inbox := make([][]tfhe.Point, total)
	for _, n := range nodes {
		publicShare, subShares, err := n.dealer.Deal(n.crp)
		if err != nil {
			t.Fatalf("deal at position %d: %v", n.position, err)
		}

		body, err := publicShare.Share.MarshalBinary()
		if err != nil {
			t.Fatalf("encode collective-key share at position %d: %v", n.position, err)
		}
		wire, err := json.Marshal(tfhePublicShare{From: n.position, Share: body})
		if err != nil {
			t.Fatalf("encode broadcast at position %d: %v", n.position, err)
		}
		var decodedPublic tfhePublicShare
		if err := json.Unmarshal(wire, &decodedPublic); err != nil {
			t.Fatalf("decode broadcast at position %d: %v", n.position, err)
		}
		share := nodes[0].ckg.AllocateShare()
		if err := share.UnmarshalBinary(decodedPublic.Share); err != nil {
			t.Fatalf("decode collective-key share at position %d: %v", n.position, err)
		}
		public = append(public, tfhe.Public{From: decodedPublic.From, Share: share})

		for _, sub := range subShares {
			wire, err := json.Marshal(tfheSubShare{From: sub.From, To: sub.To, Coeffs: sub.Coeffs})
			if err != nil {
				t.Fatalf("encode sub-share %d to %d: %v", sub.From, sub.To, err)
			}
			var decoded tfheSubShare
			if err := json.Unmarshal(wire, &decoded); err != nil {
				t.Fatalf("decode sub-share %d to %d: %v", sub.From, sub.To, err)
			}
			inbox[decoded.To-1] = append(inbox[decoded.To-1], tfhe.Point{
				From:   decoded.From,
				To:     decoded.To,
				Coeffs: decoded.Coeffs,
			})
		}
	}

	// Round 2: assemble the public key, fold the inbox into a share.
	var firstKey []byte
	members := make([]*tfhe.Member, total)
	for _, n := range nodes {
		pub, err := tfhe.Assemble(n.ckg, n.crp, public, params)
		if err != nil {
			t.Fatalf("collective public key at position %d: %v", n.position, err)
		}
		body, err := pub.MarshalBinary()
		if err != nil {
			t.Fatalf("encode collective public key at position %d: %v", n.position, err)
		}
		if n.position == 1 {
			firstKey = body
		} else if !reflect.DeepEqual(body, firstKey) {
			t.Fatalf("position %d assembled a different collective public key", n.position)
		}

		share, err := n.dealer.Aggregate(inbox[n.position-1])
		if err != nil {
			t.Fatalf("fold sub-shares at position %d: %v", n.position, err)
		}
		n.dealer.Zeroize()

		member := &tfhe.Member{
			Params:    lit,
			Threshold: threshold,
			Total:     total,
			Key:       body,
			Share:     share,
		}
		if err := member.Validate(); err != nil {
			t.Fatalf("member at position %d: %v", n.position, err)
		}
		members[n.position-1] = member
	}

	// Encrypt under the collective key, decrypt with a threshold of shares.
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	const want = uint64(0x2A)
	ciphertext, err := tfhe.Encrypt(params, pub, want, fhe.FheUint8)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	shares := make([]tfhe.Decryption, 0, threshold)
	for _, m := range members[total-threshold:] {
		prng, err := sampling.NewKeyedPRNG(append(append([]byte(nil), ceremonyNoise...), byte(m.Share.Index)))
		if err != nil {
			t.Fatalf("keyed prng: %v", err)
		}
		s, err := m.Decrypt(ciphertext, prng)
		if err != nil {
			t.Fatalf("partial decryption at position %d: %v", m.Share.Index, err)
		}
		shares = append(shares, s)
	}
	bits, err := tfhe.Decrypt(ciphertext, shares, params, threshold)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if got := tfhe.Value(bits); got != want {
		t.Fatalf("committee recovered %#x, want %#x", got, want)
	}
}

// TestTFHECeremony_ReferencePolynomialFollowsTheSeed checks the reference
// polynomial is a function of the seed alone.
func TestTFHECeremony_ReferencePolynomialFollowsTheSeed(t *testing.T) {
	params, _, err := tfheParams()
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	ordered, _ := tfhePositions([]party.ID{"node-b", "node-a"})

	reference := func(walletID string, ids []party.ID) multiparty.PublicKeyGenCRP {
		t.Helper()
		crp, _, err := tfhe.Reference(params, tfheCRSSeed(walletID, ids))
		if err != nil {
			t.Fatalf("reference polynomial: %v", err)
		}
		return crp
	}

	mine := reference("wallet-1", ordered)
	yours := reference("wallet-1", ordered)
	if !mine.Value.Q.Equal(&yours.Value.Q) {
		t.Fatal("two nodes derived different reference polynomials for one ceremony")
	}

	otherWallet := reference("wallet-2", ordered)
	if mine.Value.Q.Equal(&otherWallet.Value.Q) {
		t.Fatal("two wallets share a reference polynomial")
	}

	otherCommittee := reference("wallet-1", append(ordered, "node-c"))
	if mine.Value.Q.Equal(&otherCommittee.Value.Q) {
		t.Fatal("two committees share a reference polynomial")
	}
}

// TestTFHEWireTypesCarryNoSecretKey checks neither wire type has a field that
// could carry a whole secret key.
func TestTFHEWireTypesCarryNoSecretKey(t *testing.T) {
	forbidden := []string{"SecretKey", "SKLWE", "SKBR", "MasterKey"}
	for _, v := range []interface{}{tfhePublicShare{}, tfheSubShare{}} {
		ty := reflect.TypeOf(v)
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			field := f.Name + ":" + f.Type.String()
			for _, bad := range forbidden {
				if strings.Contains(field, bad) {
					t.Fatalf("%s field %q carries secret-key material (%q)", ty.Name(), field, bad)
				}
			}
		}
	}
}

// TestTFHEWalletKey_KnownAnswer pins the key-store name.
func TestTFHEWalletKey_KnownAnswer(t *testing.T) {
	if got, want := tfheWalletKey("wallet-1"), "tfhe:wallet-1"; got != want {
		t.Errorf("tfheWalletKey = %q, want %q", got, want)
	}
}

// TestNoWholeKeyInThresholdFHESource fails if this lane's source calls a
// whole-key generator, the trusted-dealer split, a single-party decryptor or a
// secret-key encryptor. The scheme's own source is gated the same way.
func TestNoWholeKeyInThresholdFHESource(t *testing.T) {
	forbiddenCalls := map[string]struct{}{
		"ShareLWESecretKey":       {},
		"ShareLWESecretKeyFHE":    {},
		"GenKeyPair":              {},
		"GenSecretKey":            {},
		"GenSecretKeyNew":         {},
		"NewDecryptor":            {},
		"NewBitwiseDecryptor":     {},
		"NewEncryptor":            {},
		"NewBitwiseEncryptor":     {},
		"CommitKey":               {},
		"DecryptBitFromPlaintext": {},
	}
	forbiddenNames := regexp.MustCompile(`(?i)reconstruct|recoversecret|combinesecret|recovermaster`)

	lane := []string{"tfhe*.go", "../policy/fhe_threshold*.go"}
	scanned := 0
	for _, pattern := range lane {
		matched, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		for _, path := range matched {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			scanned++
			if bad := forbiddenCall(src, forbiddenCalls, forbiddenNames); bad != "" {
				t.Errorf("%s calls %q, which would form a whole FHE key", path, bad)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no source files")
	}
}

// TestNoWholeKeyGateHasTeeth checks the gate above catches a violation.
func TestNoWholeKeyGateHasTeeth(t *testing.T) {
	src := `package x
func victim() {
	sk := whole()
	ShareLWESecretKey(sk, params, 2, 3)
}`
	f, err := parser.ParseFile(token.NewFileSet(), "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	calls := map[string]struct{}{"ShareLWESecretKey": {}}
	if bad := forbiddenCall(f, calls, regexp.MustCompile(`$^`)); bad == "" {
		t.Fatal("the gate missed an injected whole-key call")
	}
}

// forbiddenCall returns the first forbidden call target in f, or "".
func forbiddenCall(f *ast.File, calls map[string]struct{}, names *regexp.Regexp) string {
	found := ""
	ast.Inspect(f, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if name == "" {
			return true
		}
		if _, bad := calls[name]; bad {
			found = name
			return false
		}
		if names.MatchString(name) {
			found = name
			return false
		}
		return true
	})
	return found
}

// TestTFHEPositionsByNode_KnownAnswer pins the sender-to-position map.
func TestTFHEPositionsByNode_KnownAnswer(t *testing.T) {
	ordered, _ := tfhePositions([]party.ID{"node-c", "node-a", "node-b"})
	byNode := tfhePositionsByNode(ordered)
	for node, want := range map[string]int{"node-a": 1, "node-b": 2, "node-c": 3} {
		if byNode[node] != want {
			t.Errorf("%s maps to position %d, want %d", node, byNode[node], want)
		}
	}
	if _, ok := byNode["node-z"]; ok {
		t.Error("a node outside the committee has a position")
	}
}

// TestTFHEKeygen_RefusesAClaimedPosition checks a message may only speak for
// the position of the member that sent it.
func TestTFHEKeygen_RefusesAClaimedPosition(t *testing.T) {
	params, lit, err := tfheParams()
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	ids := []party.ID{"node-a", "node-b", "node-c"}
	s, err := newTFHEKeygenSession("wallet-binding", nil, "node-a", ids, 2, params, lit,
		nil, nil, nil, nil, "org")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer s.Stop()
	if s.position != 1 {
		t.Fatalf("this node is at position %d, want 1", s.position)
	}

	n := params.ParamsLWE().RingQ().N()
	coeffs := make([]uint64, n)

	// node-b (position 2) dealing a sub-share in node-c's name.
	body, err := json.Marshal(tfheSubShare{From: 3, To: 1, Coeffs: coeffs})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := s.acceptSubShare(2, body); err == nil {
		t.Fatal("a sub-share claiming another member's position was accepted")
	} else if !strings.Contains(err.Error(), "claiming position 3") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// The same member dealing for itself is accepted.
	body, err = json.Marshal(tfheSubShare{From: 2, To: 1, Coeffs: coeffs})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := s.acceptSubShare(2, body); err != nil {
		t.Fatalf("an honest sub-share was refused: %v", err)
	}

	// And the same binding on the broadcast side.
	share := s.ckg.AllocateShare()
	encoded, err := share.MarshalBinary()
	if err != nil {
		t.Fatalf("encode collective-key share: %v", err)
	}
	body, err = json.Marshal(tfhePublicShare{From: 3, Share: encoded})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := s.acceptPublicShare(2, body); err == nil {
		t.Fatal("a collective-key share claiming another member's position was accepted")
	} else if !strings.Contains(err.Error(), "claiming position 3") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestTFHEKeygen_RefusesAMisaddressedSubShare checks a sub-share is accepted
// only by the member it is addressed to.
func TestTFHEKeygen_RefusesAMisaddressedSubShare(t *testing.T) {
	params, lit, err := tfheParams()
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	s, err := newTFHEKeygenSession("wallet-addressing", nil, "node-a",
		[]party.ID{"node-a", "node-b", "node-c"}, 2, params, lit, nil, nil, nil, nil, "org")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer s.Stop()

	coeffs := make([]uint64, params.ParamsLWE().RingQ().N())
	body, err := json.Marshal(tfheSubShare{From: 2, To: 3, Coeffs: coeffs})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := s.acceptSubShare(2, body); err == nil {
		t.Fatal("a sub-share addressed to another member was accepted")
	} else if !strings.Contains(err.Error(), "addressed to position 3") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
