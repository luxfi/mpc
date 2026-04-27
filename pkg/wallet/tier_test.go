package wallet

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"
)

// All 9 tiers must have a canonical policy. If a tier is added to AllTiers
// without a policy entry — or vice versa — this test fails.
func TestAllTiersHaveCanonicalPolicies(t *testing.T) {
	policies := StandardTierPolicies()
	if len(policies) != 9 {
		t.Fatalf("expected 9 tier policies, got %d", len(policies))
	}
	if len(AllTiers) != 9 {
		t.Fatalf("expected 9 tiers in AllTiers, got %d", len(AllTiers))
	}
	for _, tier := range AllTiers {
		p, ok := policies[tier]
		if !ok {
			t.Errorf("tier %s missing canonical policy", tier)
		}
		if p.Tier != tier {
			t.Errorf("policy[%s].Tier=%s — drift", tier, p.Tier)
		}
		if p.MPCThreshold.T < 1 || p.MPCThreshold.N < p.MPCThreshold.T {
			t.Errorf("tier %s has bogus threshold %d-of-%d", tier, p.MPCThreshold.T, p.MPCThreshold.N)
		}
	}
}

// Spot-check a handful of policy invariants from the executive doc.
func TestPolicyInvariants(t *testing.T) {
	policies := StandardTierPolicies()

	if !policies[TierHot].AllowAutoApproval {
		t.Error("hot tier must allow auto-approval")
	}
	if !policies[TierHot].AllowlistRequired {
		t.Error("hot tier must require allowlist")
	}
	if policies[TierCold].AllowAutoApproval {
		t.Error("cold tier MUST NOT auto-approve")
	}
	if !policies[TierCold].AirgappedRequired {
		t.Error("cold tier must be airgapped")
	}
	if !policies[TierDR].AirgappedRequired {
		t.Error("DR tier must be airgapped")
	}
	if policies[TierQuarantine].AllowAutoApproval {
		t.Error("quarantine MUST NOT auto-approve — ever")
	}
	if policies[TierQuarantine].DailyLimitWei != "0" {
		t.Error("quarantine must have zero daily limit")
	}
	if policies[TierContractAdmin].TimelockDuration < 24*time.Hour {
		t.Error("contract_admin must have at least 24h timelock")
	}
	if policies[TierGas].KYTRequired {
		t.Error("gas tier should not require KYT (low value, allowlisted)")
	}
}

// PolicyFor must panic on invalid tier — guarantees we don't fall through
// to a zero-valued policy by accident.
func TestPolicyForInvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid tier")
		}
	}()
	_ = PolicyFor(Tier("nonsense"))
}

// Domain separation: the canonical case described in the executive doc —
// 3 nodes spread across AWS + GCP + colo passes for a hot 2-of-3 wallet.
func TestDomainSeparation_HotSpread_OK(t *testing.T) {
	r := NewInMemoryRegistry()
	w := Wallet{
		ID:        "hot-eth-001",
		OrgID:     "org-1",
		Tier:      TierHot,
		Chain:     "eip155:1",
		Address:   "0xaaaa",
		Threshold: ThresholdSpec{T: 2, N: 3},
		Nodes: []NodeBinding{
			{NodeID: "n0", CloudProvider: "aws", Account: "111", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n1", CloudProvider: "gcp", Account: "lux-mpc-prod", Region: "us-central1", HSMProvider: "gcp-cloud-hsm"},
			{NodeID: "n2", CloudProvider: "colo", Account: "sfo3-rack-01", Region: "sfo3", HSMProvider: "thales-luna"},
		},
	}
	if err := r.Create(context.Background(), w); err != nil {
		t.Fatalf("expected create OK, got %v", err)
	}
}

// 3-of-5 cold wallet across 3 cloud providers + 5 distinct HSM vendors —
// the gold-standard cold setup.
func TestDomainSeparation_Cold3of5_OK(t *testing.T) {
	r := NewInMemoryRegistry()
	w := Wallet{
		ID:        "cold-eth-treasury",
		OrgID:     "org-1",
		Tier:      TierCold,
		Chain:     "eip155:1",
		Address:   "0xbbbb",
		Threshold: ThresholdSpec{T: 3, N: 5},
		Nodes: []NodeBinding{
			{NodeID: "n0", CloudProvider: "aws", Account: "111", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n1", CloudProvider: "gcp", Account: "lux-cold", Region: "us-central1", HSMProvider: "gcp-cloud-hsm"},
			{NodeID: "n2", CloudProvider: "azure", Account: "lux-prod-az", Region: "eastus", HSMProvider: "azure-dedicated-hsm"},
			{NodeID: "n3", CloudProvider: "colo", Account: "ny5-rack", Region: "ny5", HSMProvider: "thales-luna"},
			{NodeID: "n4", CloudProvider: "onprem", Account: "vault-room", Region: "office", HSMProvider: "yubihsm"},
		},
	}
	if err := r.Create(context.Background(), w); err != nil {
		t.Fatalf("expected create OK, got %v", err)
	}
}

// 3 nodes ALL in same AWS account: must fail for cold.
func TestDomainSeparation_ColdAllSameAccount_Fails(t *testing.T) {
	r := NewInMemoryRegistry()
	w := Wallet{
		ID:        "cold-bad-001",
		OrgID:     "org-1",
		Tier:      TierCold,
		Chain:     "eip155:1",
		Address:   "0xcccc",
		Threshold: ThresholdSpec{T: 3, N: 5},
		Nodes: []NodeBinding{
			{NodeID: "n0", CloudProvider: "aws", Account: "111", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n1", CloudProvider: "aws", Account: "111", Region: "us-west-2", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n2", CloudProvider: "aws", Account: "111", Region: "eu-west-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n3", CloudProvider: "aws", Account: "111", Region: "ap-south-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n4", CloudProvider: "aws", Account: "111", Region: "ap-northeast-1", HSMProvider: "aws-cloudhsm"},
		},
	}
	err := r.Create(context.Background(), w)
	if err == nil {
		t.Fatal("expected domain-separation failure")
	}
	if !errors.Is(err, ErrDomainCollision) {
		t.Fatalf("expected ErrDomainCollision, got %v", err)
	}
}

// 3 nodes, 3 distinct AWS accounts but same provider: must fail for cold
// (cold demands 3+ distinct cloud providers).
func TestDomainSeparation_ColdSameProviderDifferentAccounts_FailsCloudFloor(t *testing.T) {
	r := NewInMemoryRegistry()
	w := Wallet{
		ID:        "cold-2",
		OrgID:     "org-1",
		Tier:      TierCold,
		Chain:     "eip155:1",
		Address:   "0xdddd",
		Threshold: ThresholdSpec{T: 3, N: 5},
		Nodes: []NodeBinding{
			{NodeID: "n0", CloudProvider: "aws", Account: "1", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n1", CloudProvider: "aws", Account: "2", Region: "us-east-2", HSMProvider: "thales-luna"},
			{NodeID: "n2", CloudProvider: "aws", Account: "3", Region: "us-west-1", HSMProvider: "yubihsm"},
			{NodeID: "n3", CloudProvider: "aws", Account: "4", Region: "us-west-2", HSMProvider: "zymbit"},
			{NodeID: "n4", CloudProvider: "aws", Account: "5", Region: "eu-west-1", HSMProvider: "azure-dedicated-hsm"},
		},
	}
	err := r.Create(context.Background(), w)
	if err == nil {
		t.Fatal("expected cloud-spread failure")
	}
	if !errors.Is(err, ErrInsufficientCloud) {
		t.Fatalf("expected ErrInsufficientCloud, got %v", err)
	}
}

// Hot tier 2-of-3 in the SAME AWS account fails (collision) — even though
// hot only demands 2 distinct clouds, the same-account rule is absolute.
func TestDomainSeparation_HotSameAccount_Fails(t *testing.T) {
	r := NewInMemoryRegistry()
	w := Wallet{
		ID:        "hot-bad",
		OrgID:     "org-1",
		Tier:      TierHot,
		Chain:     "eip155:1",
		Address:   "0xeeee",
		Threshold: ThresholdSpec{T: 2, N: 3},
		Nodes: []NodeBinding{
			{NodeID: "n0", CloudProvider: "aws", Account: "111", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n1", CloudProvider: "aws", Account: "111", Region: "us-west-2", HSMProvider: "thales-luna"},
			{NodeID: "n2", CloudProvider: "gcp", Account: "p", Region: "us-central1", HSMProvider: "yubihsm"},
		},
	}
	err := r.Create(context.Background(), w)
	if !errors.Is(err, ErrDomainCollision) {
		t.Fatalf("expected ErrDomainCollision, got %v", err)
	}
}

// Gas tier disables NodeDomainSeparation, so 3 nodes in the same account
// is allowed (gas wallets are throw-away anyway).
func TestDomainSeparation_GasCollocated_OK(t *testing.T) {
	r := NewInMemoryRegistry()
	w := Wallet{
		ID:        "gas-eth-001",
		OrgID:     "org-1",
		Tier:      TierGas,
		Chain:     "eip155:1",
		Address:   "0xffff",
		Threshold: ThresholdSpec{T: 2, N: 3},
		Nodes: []NodeBinding{
			{NodeID: "n0", CloudProvider: "aws", Account: "111", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n1", CloudProvider: "aws", Account: "111", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n2", CloudProvider: "aws", Account: "111", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
		},
	}
	if err := r.Create(context.Background(), w); err != nil {
		t.Fatalf("gas wallet should accept collocated nodes, got %v", err)
	}
}

// Threshold mismatch: declaring a "cold" tier with 2-of-3 must fail.
func TestCreateRejectsThresholdMismatch(t *testing.T) {
	r := NewInMemoryRegistry()
	w := Wallet{
		ID:        "cold-wrong-threshold",
		OrgID:     "org-1",
		Tier:      TierCold,
		Chain:     "eip155:1",
		Address:   "0x0",
		Threshold: ThresholdSpec{T: 2, N: 3},
		Nodes: []NodeBinding{
			{NodeID: "n0", CloudProvider: "aws", Account: "1", Region: "us-east-1", HSMProvider: "aws-cloudhsm"},
			{NodeID: "n1", CloudProvider: "gcp", Account: "p", Region: "us-central1", HSMProvider: "gcp-cloud-hsm"},
			{NodeID: "n2", CloudProvider: "colo", Account: "sfo3", Region: "sfo3", HSMProvider: "thales-luna"},
		},
	}
	err := r.Create(context.Background(), w)
	if !errors.Is(err, ErrThresholdMismatch) {
		t.Fatalf("expected ErrThresholdMismatch, got %v", err)
	}
}

// Velocity counters: hot tier per-tx=10 ETH, velocity=20 ETH/hr.
// Charge 10 + 10 = 20 ETH inside the window — both succeed. A third 10
// ETH charge inside the same window pushes us to 30 ETH and must fail
// against the velocity cap. Rolling 2h forward (past the 1h window)
// drops the earlier hits and the third charge succeeds.
func TestVelocityWindowRollover(t *testing.T) {
	store := NewUsageStore()
	policy := PolicyFor(TierHot)
	wei := func(eth int64) *big.Int {
		v := big.NewInt(eth)
		return v.Mul(v, big.NewInt(1_000_000_000_000_000_000))
	}
	t0 := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	if err := store.CheckAndCharge("w1", wei(10), policy, t0); err != nil {
		t.Fatalf("first 10 ETH charge should succeed, got %v", err)
	}
	if err := store.CheckAndCharge("w1", wei(10), policy, t0.Add(5*time.Minute)); err != nil {
		t.Fatalf("second 10 ETH charge should succeed (cap exactly), got %v", err)
	}
	// Window total now 20 ETH (== cap). One more 10 ETH charge goes to 30.
	err := store.CheckAndCharge("w1", wei(10), policy, t0.Add(10*time.Minute))
	if !errors.Is(err, ErrVelocityExceeded) {
		t.Fatalf("expected ErrVelocityExceeded, got %v", err)
	}
	// Roll past the window — earlier hits drop out, charge succeeds.
	if err := store.CheckAndCharge("w1", wei(10), policy, t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("post-window charge should succeed, got %v", err)
	}
}

// Per-tx limit: a 50 ETH single tx on hot must fail (per-tx cap = 10 ETH).
func TestPerTxLimit(t *testing.T) {
	store := NewUsageStore()
	policy := PolicyFor(TierHot)
	wei := func(eth int64) *big.Int {
		v := big.NewInt(eth)
		return v.Mul(v, big.NewInt(1_000_000_000_000_000_000))
	}
	err := store.CheckAndCharge("w2", wei(50), policy, time.Now())
	if !errors.Is(err, ErrPerTxLimitExceeded) {
		t.Fatalf("expected ErrPerTxLimitExceeded, got %v", err)
	}
}

// Daily cap: hot wallet limit 100 ETH/day. 10 charges of 10 ETH succeed,
// 11th fails with ErrDailyLimitExceeded.
func TestDailyLimitAndReset(t *testing.T) {
	store := NewUsageStore()
	policy := PolicyFor(TierHot)
	wei := func(eth int64) *big.Int {
		v := big.NewInt(eth)
		return v.Mul(v, big.NewInt(1_000_000_000_000_000_000))
	}
	t0 := time.Date(2026, 4, 27, 0, 1, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		// Spread across velocity windows so velocity doesn't bite first.
		ts := t0.Add(time.Duration(i+1) * 2 * time.Hour)
		if err := store.CheckAndCharge("d1", wei(10), policy, ts); err != nil {
			t.Fatalf("charge %d/10 should succeed, got %v", i, err)
		}
	}
	err := store.CheckAndCharge("d1", wei(10), policy, t0.Add(22*time.Hour))
	if !errors.Is(err, ErrDailyLimitExceeded) {
		t.Fatalf("expected ErrDailyLimitExceeded, got %v", err)
	}

	// Roll into next UTC day — daily resets, velocity window also clear.
	tomorrow := t0.Add(48 * time.Hour)
	if err := store.CheckAndCharge("d1", wei(10), policy, tomorrow); err != nil {
		t.Fatalf("post-midnight charge should succeed, got %v", err)
	}
}

// "inf" limit: cold tier per-tx is unbounded. A 1B-ETH charge passes the
// per-tx check (it would still fail other tier checks like timelock, but
// not at this layer).
func TestInfLimit(t *testing.T) {
	store := NewUsageStore()
	policy := PolicyFor(TierCold)
	huge, _ := new(big.Int).SetString("1000000000000000000000000000", 10) // 1B ETH in wei
	if err := store.CheckAndCharge("cold", huge, policy, time.Now()); err != nil {
		t.Fatalf("cold per-tx should be unbounded, got %v", err)
	}
}

// View returns parsed counters in JSON-friendly shape.
func TestUsageView(t *testing.T) {
	store := NewUsageStore()
	policy := PolicyFor(TierHot)
	wei := big.NewInt(1).Mul(big.NewInt(1), big.NewInt(1_000_000_000_000_000_000)) // 1 ETH
	now := time.Date(2026, 4, 27, 9, 0, 0, 0, time.UTC)
	_ = store.CheckAndCharge("v1", wei, policy, now)

	view, err := store.View("v1", policy, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("View err: %v", err)
	}
	if view.WalletID != "v1" {
		t.Errorf("walletID drift: %s", view.WalletID)
	}
	if view.HitsInWindow != 1 {
		t.Errorf("expected 1 hit in window, got %d", view.HitsInWindow)
	}
	if view.DailyUsedWei != "1000000000000000000" {
		t.Errorf("daily used wei wrong: %s", view.DailyUsedWei)
	}
}

// Quarantine tier rejects every charge — DailyLimitWei="0".
func TestQuarantineRejectsAllCharges(t *testing.T) {
	store := NewUsageStore()
	policy := PolicyFor(TierQuarantine)
	err := store.CheckAndCharge("q1", big.NewInt(1), policy, time.Now())
	if err == nil {
		t.Fatal("quarantine must reject any charge")
	}
}
