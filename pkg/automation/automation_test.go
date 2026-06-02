package automation

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// GasStation
// =============================================================================

type fakeChain struct {
	balances   map[string]*big.Int // addr -> wei
	sentLog    []sentTx
	balanceErr error
	sendErr    error
}

type sentTx struct {
	chain, from, to string
	amount          *big.Int
}

func (f *fakeChain) Balance(_ context.Context, _, addr string) (*big.Int, error) {
	if f.balanceErr != nil {
		return nil, f.balanceErr
	}
	if v, ok := f.balances[addr]; ok {
		return new(big.Int).Set(v), nil
	}
	return new(big.Int), nil
}

func (f *fakeChain) SendValue(_ context.Context, chain, from, to string, amt *big.Int) (string, error) {
	if f.sendErr != nil {
		return "", f.sendErr
	}
	f.sentLog = append(f.sentLog, sentTx{chain: chain, from: from, to: to, amount: new(big.Int).Set(amt)})
	if f.balances == nil {
		f.balances = map[string]*big.Int{}
	}
	cur := f.balances[to]
	if cur == nil {
		cur = new(big.Int)
	}
	f.balances[to] = new(big.Int).Add(cur, amt)
	return "0xtest", nil
}

func TestGasStation_TopUpBelowFloor(t *testing.T) {
	chain := &fakeChain{balances: map[string]*big.Int{
		"hot1": big.NewInt(50),
	}}
	g := NewGasStation(chain)
	if err := g.Set(GasRule{
		OrgID:         "org1",
		Chain:         "ethereum",
		ReserveWallet: "reserve",
		TargetWallets: []string{"hot1"},
		Floor:         big.NewInt(100),
		Target:        big.NewInt(500),
		CapPerTick:    big.NewInt(10000),
		Enabled:       true,
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	results, err := g.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if len(r.Receipts) != 1 || r.Receipts[0].SkipReason != "" {
		t.Fatalf("want one successful topup, got %+v", r.Receipts)
	}
	if r.Receipts[0].SentWei != "450" {
		t.Errorf("want sent=450 (target500 - bal50), got %s", r.Receipts[0].SentWei)
	}
	if len(chain.sentLog) != 1 || chain.sentLog[0].amount.Cmp(big.NewInt(450)) != 0 {
		t.Errorf("send log mismatch: %+v", chain.sentLog)
	}
}

func TestGasStation_AboveFloorSkipped(t *testing.T) {
	chain := &fakeChain{balances: map[string]*big.Int{"hot1": big.NewInt(200)}}
	g := NewGasStation(chain)
	_ = g.Set(GasRule{
		OrgID: "org1", Chain: "ethereum", ReserveWallet: "reserve",
		TargetWallets: []string{"hot1"},
		Floor:         big.NewInt(100), Target: big.NewInt(500), CapPerTick: big.NewInt(10000),
		Enabled: true,
	})
	results, err := g.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if results[0].Receipts[0].SkipReason != "above floor" {
		t.Errorf("want skip 'above floor', got %q", results[0].Receipts[0].SkipReason)
	}
	if len(chain.sentLog) != 0 {
		t.Errorf("expected no send, got %+v", chain.sentLog)
	}
}

func TestGasStation_CapPerTickHonored(t *testing.T) {
	chain := &fakeChain{balances: map[string]*big.Int{"hot1": big.NewInt(0)}}
	g := NewGasStation(chain)
	_ = g.Set(GasRule{
		OrgID: "org1", Chain: "ethereum", ReserveWallet: "reserve",
		TargetWallets: []string{"hot1"},
		Floor:         big.NewInt(100), Target: big.NewInt(10000), CapPerTick: big.NewInt(50),
		Enabled: true,
	})
	results, _ := g.Tick(context.Background())
	if got := results[0].Receipts[0].SentWei; got != "50" {
		t.Errorf("cap not honored — sent %s, want 50", got)
	}
}

func TestGasStation_ValidateRejectsBadRule(t *testing.T) {
	bad := GasRule{OrgID: "x", Chain: "y", ReserveWallet: "r", TargetWallets: []string{"a"},
		Floor: big.NewInt(10), Target: big.NewInt(5), CapPerTick: big.NewInt(1)}
	if err := bad.Validate(); err == nil {
		t.Error("expected target<=floor to fail validation")
	}
}

func TestGasStation_BalanceError(t *testing.T) {
	chain := &fakeChain{balanceErr: errors.New("rpc down")}
	g := NewGasStation(chain)
	_ = g.Set(GasRule{
		OrgID: "org1", Chain: "ethereum", ReserveWallet: "reserve",
		TargetWallets: []string{"hot1"},
		Floor:         big.NewInt(100), Target: big.NewInt(500), CapPerTick: big.NewInt(10000),
		Enabled: true,
	})
	results, _ := g.Tick(context.Background())
	if results[0].Receipts[0].SkipReason == "" {
		t.Error("expected SkipReason on balance error")
	}
}

// =============================================================================
// SmartTransfer
// =============================================================================

func TestSmartTransfer_PicksCheapest(t *testing.T) {
	st := NewSmartTransfer()
	st.Add(NewOnChainProvider("ethereum", 50, 30*time.Second))
	st.Add(NewBridgeProvider("luxbridge", "ethereum", "lux", 25, 5*time.Minute))

	req := TransferRequest{
		OrgID:  "org1",
		Asset:  "USDC",
		Amount: big.NewInt(1_000_000),
		From:   "0xfrom",
		To:     "0xto",
	}
	best, err := st.Best(context.Background(), req)
	if err != nil {
		t.Fatalf("Best: %v", err)
	}
	if best.FeeBps != 25 {
		t.Errorf("want cheapest 25bps, got %d", best.FeeBps)
	}
	quotes, _ := st.Quote(context.Background(), req)
	if len(quotes) != 2 || quotes[0].FeeBps > quotes[1].FeeBps {
		t.Errorf("quotes not sorted: %+v", quotes)
	}
}

func TestSmartTransfer_NoProviders(t *testing.T) {
	st := NewSmartTransfer()
	_, err := st.Best(context.Background(), TransferRequest{
		OrgID:  "x",
		Asset:  "A",
		Amount: big.NewInt(1),
		From:   "f",
		To:     "t",
	})
	if err == nil {
		t.Error("expected error with zero providers")
	}
}

func TestSmartTransfer_RejectsBadRequest(t *testing.T) {
	st := NewSmartTransfer()
	st.Add(NewOnChainProvider("ethereum", 5, time.Second))
	_, err := st.Best(context.Background(), TransferRequest{Asset: "A"})
	if err == nil {
		t.Error("expected validation error for missing fields")
	}
}

func TestSmartTransfer_OnChainFeeAbsCorrect(t *testing.T) {
	st := NewSmartTransfer()
	st.Add(NewOnChainProvider("ethereum", 50, time.Second)) // 0.5%
	q, _ := st.Best(context.Background(), TransferRequest{
		OrgID: "o", Asset: "A", From: "f", To: "t",
		Amount: big.NewInt(1_000_000),
	})
	// 0.5% of 1_000_000 = 5_000.
	if q.FeeAbs != "5000" {
		t.Errorf("want feeAbs=5000, got %s", q.FeeAbs)
	}
}

// =============================================================================
// FeeBump — EVM
// =============================================================================

func TestEVMBump_Legacy(t *testing.T) {
	in := EVMBumpInput{GasPrice: big.NewInt(20_000_000_000)} // 20 gwei
	plan, err := EVMBump(in, 2500)                           // 25%
	if err != nil {
		t.Fatalf("EVMBump: %v", err)
	}
	if plan.Mode != "legacy" {
		t.Errorf("want mode legacy, got %s", plan.Mode)
	}
	want := big.NewInt(25_000_000_000)
	if plan.GasPrice.Cmp(want) != 0 {
		t.Errorf("want gasPrice %s, got %s", want, plan.GasPrice)
	}
}

func TestEVMBump_EIP1559(t *testing.T) {
	in := EVMBumpInput{
		MaxFeePerGas:         big.NewInt(30_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(2_000_000_000),
	}
	plan, err := EVMBump(in, 1000) // 10%
	if err != nil {
		t.Fatalf("EVMBump: %v", err)
	}
	if plan.Mode != "eip1559" {
		t.Errorf("want eip1559, got %s", plan.Mode)
	}
	if plan.MaxFeePerGas.Cmp(big.NewInt(33_000_000_000)) != 0 {
		t.Errorf("max fee not bumped: %s", plan.MaxFeePerGas)
	}
	if plan.MaxPriorityFeePerGas.Cmp(big.NewInt(2_200_000_000)) != 0 {
		t.Errorf("priority not bumped: %s", plan.MaxPriorityFeePerGas)
	}
	// Invariant: max >= priority.
	if plan.MaxFeePerGas.Cmp(plan.MaxPriorityFeePerGas) < 0 {
		t.Error("invariant violated: maxFee < priority")
	}
}

func TestEVMBump_NoFeeFields(t *testing.T) {
	if _, err := EVMBump(EVMBumpInput{}, 1000); err == nil {
		t.Error("expected error with no fee fields")
	}
}

func TestEVMBump_PreservesInvariantWhenPriorityExceedsMax(t *testing.T) {
	// Edge case: caller already in a bad state. Bump must heal.
	in := EVMBumpInput{
		MaxFeePerGas:         big.NewInt(10),
		MaxPriorityFeePerGas: big.NewInt(50),
	}
	plan, _ := EVMBump(in, 1000)
	if plan.MaxFeePerGas.Cmp(plan.MaxPriorityFeePerGas) < 0 {
		t.Errorf("bump did not heal invariant: max=%s prio=%s",
			plan.MaxFeePerGas, plan.MaxPriorityFeePerGas)
	}
}

// =============================================================================
// FeeBump — BTC
// =============================================================================

func TestBTCBump_AppliesBumpAboveFloor(t *testing.T) {
	in := BTCBumpInput{
		OldFeeSat:       big.NewInt(1500),
		VSize:           150,
		MinFeeRateSatVB: 1,
		IncrementSatVB:  1,
		Inputs:          []string{"abc:0"},
		NSequenceMaxAll: 0x00000000, // RBF
	}
	plan, err := BTCBump(in, 2500) // 25%
	if err != nil {
		t.Fatalf("BTCBump: %v", err)
	}
	// 25% of 1500 = 375; 1500 + 375 = 1875.
	// Floor bump = 1*150 = 150 -> 1650. Bumped (1875) > floor — bumped wins.
	if plan.NewFeeSat.Cmp(big.NewInt(1875)) != 0 {
		t.Errorf("want fee 1875, got %s", plan.NewFeeSat)
	}
}

func TestBTCBump_RejectsNonRBFInputs(t *testing.T) {
	in := BTCBumpInput{
		OldFeeSat:       big.NewInt(1500),
		VSize:           150,
		NSequenceMaxAll: 0xfffffffe, // explicitly non-RBF
	}
	if _, err := BTCBump(in, 1000); err == nil {
		t.Error("expected error for non-RBF inputs")
	}
}

func TestBTCBump_RaisesToNetworkMinimum(t *testing.T) {
	in := BTCBumpInput{
		OldFeeSat:       big.NewInt(100),
		VSize:           150,
		MinFeeRateSatVB: 5, // mempool floor 5 sat/vB
		NSequenceMaxAll: 0x00,
	}
	plan, err := BTCBump(in, 1000) // 10%
	if err != nil {
		t.Fatalf("BTCBump: %v", err)
	}
	// 10% of 100 = 10; 100+10=110 -> rate 0 sat/vB, below 5.
	// Must raise to 5*150 = 750.
	if plan.NewFeeRateSatVB != 5 {
		t.Errorf("want rate 5, got %d", plan.NewFeeRateSatVB)
	}
	if plan.NewFeeSat.Cmp(big.NewInt(750)) != 0 {
		t.Errorf("want fee 750, got %s", plan.NewFeeSat)
	}
}

func TestBTCBump_RejectsBadInputs(t *testing.T) {
	cases := []BTCBumpInput{
		{OldFeeSat: nil, VSize: 100, NSequenceMaxAll: 0},
		{OldFeeSat: big.NewInt(0), VSize: 100, NSequenceMaxAll: 0},
		{OldFeeSat: big.NewInt(100), VSize: 0, NSequenceMaxAll: 0},
	}
	for i, c := range cases {
		if _, err := BTCBump(c, 1000); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestFormatPlan(t *testing.T) {
	evm := EVMBumpPlan{Mode: "legacy", GasPrice: big.NewInt(25_000_000_000), BumpFactorBps: 2500}
	if got := FormatPlan(evm); got == "" {
		t.Error("FormatPlan(EVMBumpPlan) empty")
	}
	btc := BTCBumpPlan{NewFeeSat: big.NewInt(1875), NewFeeRateSatVB: 12, BumpFactorBps: 2500}
	if got := FormatPlan(btc); got == "" {
		t.Error("FormatPlan(BTCBumpPlan) empty")
	}
}
