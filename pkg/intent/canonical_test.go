package intent

import (
	"bytes"
	"testing"
	"time"
)

// fixture returns a fully-populated CanonicalIntent for tests. All fields
// are deterministic so digests are stable across runs.
func fixture() *CanonicalIntent {
	return &CanonicalIntent{
		IntentVersion:  IntentVersion,
		SessionID:      "sess-01HXYZ",
		WalletID:       "wallet-treasury-eth",
		WalletTier:     TierWarm,
		Chain:          "eip155:1",
		Asset:          "ETH",
		From:           "0xfrom",
		To:             "0xto",
		Amount:         "1000000000000000000", // 1 ETH wei
		MaxFee:         "21000000000000",
		Nonce:          "42",
		CalldataHash:   [32]byte{0x01, 0x02, 0x03},
		HumanSummary:   "send 1 ETH from treasury to vendor X",
		PolicyID:       "policy-warm-v3",
		PolicyHash:     [32]byte{0xaa, 0xbb, 0xcc},
		RiskVerdictID:  "risk-2026-04-27-001",
		SimulationHash: [32]byte{0xde, 0xad, 0xbe, 0xef},
		ExpiresAt:      time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC),
	}
}

func TestDigest_Stable(t *testing.T) {
	ci := fixture()
	d1, err := ci.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d2, err := ci.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("digest not stable: %x != %x", d1, d2)
	}
}

func TestDigest_DifferentFieldsDifferentDigest(t *testing.T) {
	a := fixture()
	b := fixture()
	b.Amount = "999"
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da == db {
		t.Fatalf("digest must change when amount changes")
	}
}

// TestDigest_ApprovalsExcluded — approvals must NOT participate in the
// digest because approvals are signatures over the digest. Including them
// would make the digest depend on the signatures, which is circular.
func TestDigest_ApprovalsExcluded(t *testing.T) {
	a := fixture()
	b := fixture()
	b.Approvals = []ApprovalSignature{{
		SignerID:  "exec-1",
		PublicKey: bytes.Repeat([]byte{1}, 32),
		Signature: bytes.Repeat([]byte{2}, 64),
		SignedAt:  time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC),
	}}
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db {
		t.Fatalf("digest must NOT change when approvals are added: %x != %x", da, db)
	}
}

func TestDigest_NodeAttestationsExcluded(t *testing.T) {
	a := fixture()
	b := fixture()
	b.NodeAttestations = []NodeAttestation{{
		NodeID:    "node0",
		PublicKey: bytes.Repeat([]byte{3}, 32),
		Verdict:   "approve",
		Signature: bytes.Repeat([]byte{4}, 64),
		SignedAt:  time.Date(2026, 4, 27, 11, 5, 0, 0, time.UTC),
	}}
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db {
		t.Fatalf("digest must NOT change when node attestations are added: %x != %x", da, db)
	}
}

// TestMarshalRoundtrip — full intent (with approvals) survives CBOR
// encode/decode cycle.
func TestMarshalRoundtrip(t *testing.T) {
	ci := fixture()
	ci.Approvals = []ApprovalSignature{{
		SignerID:  "exec-cfo",
		PublicKey: bytes.Repeat([]byte{0x10}, 32),
		Signature: bytes.Repeat([]byte{0x20}, 64),
		SignedAt:  time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC),
	}}
	enc, err := ci.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Unmarshal(enc)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SessionID != ci.SessionID || got.WalletID != ci.WalletID {
		t.Fatalf("roundtrip mismatch")
	}
	if len(got.Approvals) != 1 || got.Approvals[0].SignerID != "exec-cfo" {
		t.Fatalf("approvals roundtrip mismatch")
	}
	// Digests must match across the boundary.
	d1, _ := ci.Digest()
	d2, _ := got.Digest()
	if d1 != d2 {
		t.Fatalf("digest survived roundtrip mismatch: %x != %x", d1, d2)
	}
}

// TestMarshal_DeterministicByteIdentity — two independently-built intents
// with the same body must produce byte-identical CBOR. This is what makes
// the digest reproducible across nodes.
func TestMarshal_DeterministicByteIdentity(t *testing.T) {
	a := fixture()
	b := fixture()
	ea, err := a.Marshal()
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	eb, err := b.Marshal()
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if !bytes.Equal(ea, eb) {
		t.Fatalf("deterministic encoding failed: %x != %x", ea, eb)
	}
}

func TestValidate_OK(t *testing.T) {
	if err := fixture().Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidate_RejectsBadVersion(t *testing.T) {
	ci := fixture()
	ci.IntentVersion = "0"
	if err := ci.Validate(); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestValidate_RejectsInvalidTier(t *testing.T) {
	ci := fixture()
	ci.WalletTier = WalletTier("nonsense")
	if err := ci.Validate(); err == nil {
		t.Fatal("expected error for invalid tier")
	}
}

func TestValidate_RejectsZeroExpiry(t *testing.T) {
	ci := fixture()
	ci.ExpiresAt = time.Time{}
	if err := ci.Validate(); err == nil {
		t.Fatal("expected error for zero expiry")
	}
}

func TestWalletTier_IsValid(t *testing.T) {
	cases := []struct {
		t  WalletTier
		ok bool
	}{
		{TierHot, true},
		{TierWarm, true},
		{TierCold, true},
		{TierGas, true},
		{TierBridge, true},
		{TierContractAdmin, true},
		{TierValidator, true},
		{TierQuarantine, true},
		{TierDR, true},
		{WalletTier(""), false},
		{WalletTier("foo"), false},
	}
	for _, c := range cases {
		if c.t.IsValid() != c.ok {
			t.Errorf("IsValid(%q) = %v, want %v", c.t, c.t.IsValid(), c.ok)
		}
	}
}
