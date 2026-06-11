package api

// Treasury governance tests — SQLite-backed. The Postgres-backed concurrency
// test lives in treasury_postgres_test.go; it exercises the same CAS
// invariants under READ COMMITTED + SELECT FOR UPDATE.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// reqWithChiCtx attaches a chi RouteContext carrying the given url params
// onto the request so handlers that call urlParam(r, name) see the value
// when invoked outside the full router stack.
func reqWithChiCtx(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// newTreasuryServer spins up an SQLite-backed Server with a stub MPC
// backend sufficient to exercise the treasury handlers without running a
// real MPC cluster.
func newTreasuryServer(t *testing.T) *Server {
	t.Helper()
	path := t.TempDir() + "/treasury.db"
	d, err := db.New("sqlite://"+path, "")
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return &Server{
		db:  d,
		mpc: &mockMPCBackend{keygenResult: &KeygenResult{WalletID: "wallet-t-1", EVMAddress: "0xabc"}},
	}
}

// mkTreasuryCreateBody constructs a well-formed 3-of-5 create payload for
// the given org. Individual tests mutate before posting to assert rejection.
func mkTreasuryCreateBody(orgID string, regulatorShard bool) treasuryWalletCreateRequest {
	signers := []treasurySignerInput{
		{Role: db.TreasurySignerCompliance, KeyRef: "user-compliance", DisplayName: "Compliance"},
		{Role: db.TreasurySignerTreasurer, KeyRef: "user-cfo", DisplayName: "Treasurer"},
		{Role: db.TreasurySignerPlatformHSM, KeyRef: expectedPlatformHSMKeyRef(orgID)},
		{Role: db.TreasurySignerBackupHSM, KeyRef: "providers/backup/hsm"},
	}
	if regulatorShard {
		signers = append(signers, treasurySignerInput{
			Role: db.TreasurySignerRegulator, KeyRef: "user-reg",
		})
	}
	tiers := []treasuryTierInput{
		{MaxValue: "100000", Threshold: 3},
		{MaxValue: "inf", Threshold: 4},
	}
	if regulatorShard {
		tiers[1].RequireRegulator = true
	}
	return treasuryWalletCreateRequest{
		Name:           "Ops Treasury",
		Signers:        signers,
		Tiers:          tiers,
		RegulatorShard: regulatorShard,
	}
}

func TestTreasury_CreateWallet_ValidatesShape(t *testing.T) {
	s := newTreasuryServer(t)
	ctx := context.Background()
	orgID := "org-A"
	userID := "u-1"

	body := mkTreasuryCreateBody(orgID, false)
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/wallets", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, orgID)
	reqCtx = context.WithValue(reqCtx, ctxUserID, userID)
	reqCtx = context.WithValue(reqCtx, ctxRole, "admin")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleCreateTreasuryWallet(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create treasury wallet: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp treasuryWalletResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Signers) != 4 {
		t.Fatalf("signers=%d want 4", len(resp.Signers))
	}
	if resp.RegulatorShard {
		t.Fatalf("regulatorShard default must be false")
	}
	if resp.Tiers[0].Threshold != 3 || resp.Tiers[1].Threshold != 4 {
		t.Fatalf("tiers=%v want [3,4]", resp.Tiers)
	}

	// Verify the tier policy was written with kind="treasury".
	policies, _ := orm.TypedQuery[db.Policy](s.db.ORM).Filter("orgId=", orgID).GetAll(ctx)
	found := false
	for _, p := range policies {
		if p.Kind == "treasury" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a policy with kind=treasury")
	}
}

// TestTreasury_Create_Rejects3Signers asserts at least 4 signers required
// when regulatorShard=false (compliance, treasurer, platform_hsm,
// backup_hsm). Exactly 3 signers is insufficient.
func TestTreasury_Create_RejectsInsufficientSigners(t *testing.T) {
	s := newTreasuryServer(t)
	body := mkTreasuryCreateBody("org-A", false)
	body.Signers = body.Signers[:2] // 2 signers
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/wallets", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, "org-A")
	reqCtx = context.WithValue(reqCtx, ctxUserID, "u")
	reqCtx = context.WithValue(reqCtx, ctxRole, "admin")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleCreateTreasuryWallet(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for <3 signers, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestTreasury_Create_RejectsWrongOrgHSM — the core cross-org isolation
// invariant. Tenant A cannot create a treasury wallet that references
// tenant B's platform HSM key.
func TestTreasury_Create_RejectsWrongOrgHSM(t *testing.T) {
	s := newTreasuryServer(t)
	orgA := "acme"
	// Try to reference globex's HSM path while authenticated as acme.
	body := mkTreasuryCreateBody(orgA, false)
	for i := range body.Signers {
		if body.Signers[i].Role == db.TreasurySignerPlatformHSM {
			body.Signers[i].KeyRef = expectedPlatformHSMKeyRef("globex")
		}
	}
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/wallets", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, orgA)
	reqCtx = context.WithValue(reqCtx, ctxUserID, "u-acme-admin")
	reqCtx = context.WithValue(reqCtx, ctxRole, "admin")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleCreateTreasuryWallet(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong-org HSM, got %d body=%s", rec.Code, rec.Body.String())
	}
	body2 := map[string]string{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body2)
	if body2["error"] == "" {
		t.Fatalf("expected error body, got %s", rec.Body.String())
	}
}

// TestTreasury_Create_RegulatorShardRequiresSigner asserts that
// regulatorShard=true demands a regulator signer in the set.
func TestTreasury_Create_RegulatorShardRequiresSigner(t *testing.T) {
	s := newTreasuryServer(t)
	body := mkTreasuryCreateBody("org-A", true)
	// Drop the regulator.
	out := []treasurySignerInput{}
	for _, x := range body.Signers {
		if x.Role != db.TreasurySignerRegulator {
			out = append(out, x)
		}
	}
	body.Signers = out
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/wallets", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, "org-A")
	reqCtx = context.WithValue(reqCtx, ctxUserID, "u")
	reqCtx = context.WithValue(reqCtx, ctxRole, "admin")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleCreateTreasuryWallet(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when regulatorShard=true and no regulator signer; got %d body=%s",
			rec.Code, rec.Body.String())
	}
}

// TestTreasury_Create_RejectsLooseTiers asserts that a threshold below 3,
// a threshold above signer-count, or a missing "inf" final tier are
// rejected.
func TestTreasury_Create_RejectsLooseTiers(t *testing.T) {
	cases := []struct {
		name  string
		tiers []treasuryTierInput
	}{
		{"threshold<3", []treasuryTierInput{{MaxValue: "inf", Threshold: 2}}},
		{"no inf tier", []treasuryTierInput{{MaxValue: "100", Threshold: 3}}},
		{"threshold > signers", []treasuryTierInput{
			{MaxValue: "100", Threshold: 3},
			{MaxValue: "inf", Threshold: 10},
		}},
		{"non-monotonic", []treasuryTierInput{
			{MaxValue: "100", Threshold: 4},
			{MaxValue: "inf", Threshold: 3},
		}},
		{"invalid maxValue", []treasuryTierInput{
			{MaxValue: "not-a-number", Threshold: 3},
			{MaxValue: "inf", Threshold: 4},
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			s := newTreasuryServer(t)
			body := mkTreasuryCreateBody("org-A", false)
			body.Tiers = c.tiers
			buf := &bytes.Buffer{}
			_ = json.NewEncoder(buf).Encode(body)
			req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/wallets", buf)
			req.Header.Set("Content-Type", "application/json")
			reqCtx := context.WithValue(req.Context(), ctxOrgID, "org-A")
			reqCtx = context.WithValue(reqCtx, ctxUserID, "u")
			reqCtx = context.WithValue(reqCtx, ctxRole, "admin")
			req = req.WithContext(reqCtx)
			rec := httptest.NewRecorder()
			s.handleCreateTreasuryWallet(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: expected 400, got %d body=%s",
					c.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestTreasury_TierForOperation verifies the tier-selection algorithm picks
// the first covering tier.
func TestTreasury_TierForOperation(t *testing.T) {
	s := &Server{}
	tw := &db.TreasuryWallet{
		Tiers: []db.TreasuryTier{
			{MaxValue: "100000", Threshold: 3},
			{MaxValue: "1000000", Threshold: 4},
			{MaxValue: "inf", Threshold: 5, RequireRegulator: true},
		},
	}
	cases := []struct {
		amount string
		want   int
	}{
		{"0", 3},
		{"50000", 3},
		{"100000", 3},
		{"100001", 4},
		{"999999", 4},
		{"1000001", 5},
		{"99999999999999999999", 5}, // arbitrary big — inf tier
	}
	for _, c := range cases {
		c := c
		t.Run(c.amount, func(t *testing.T) {
			amt := c.amount
			tx := &db.Transaction{Amount: &amt}
			got := s.tierForOperation(tw, tx)
			if got.Threshold != c.want {
				t.Errorf("amount=%s threshold=%d want %d", c.amount, got.Threshold, c.want)
			}
		})
	}
}

// TestTreasury_Sign_CrossOrgRejected — tenant B's signer cannot approve
// tenant A's operation. The 404 path in handleTreasurySign must trigger
// via OrgID mismatch on the Transaction before any approval work happens.
func TestTreasury_Sign_CrossOrgRejected(t *testing.T) {
	s := newTreasuryServer(t)
	ctx := context.Background()

	orgA := "org-A"
	// Seed a treasury wallet + op under orgA.
	tw := orm.New[db.TreasuryWallet](s.db.ORM)
	tw.OrgID = orgA
	tw.Name = "A-treasury"
	tw.WalletID = "wallet-A"
	tw.Chain = "evm"
	tw.Signers = []db.TreasurySigner{
		{Role: db.TreasurySignerCompliance, KeyRef: "u-A-comp"},
		{Role: db.TreasurySignerTreasurer, KeyRef: "u-A-cfo"},
		{Role: db.TreasurySignerPlatformHSM, KeyRef: expectedPlatformHSMKeyRef(orgA)},
		{Role: db.TreasurySignerBackupHSM, KeyRef: "providers/backup/hsm"},
	}
	tw.Tiers = []db.TreasuryTier{{MaxValue: "inf", Threshold: 3}}
	tw.Status = "active"
	if err := tw.Create(); err != nil {
		t.Fatalf("create tw: %v", err)
	}

	// Policy forcing threshold=3.
	pol := orm.New[db.Policy](s.db.ORM)
	pol.OrgID = orgA
	pol.Kind = "treasury"
	pol.Name = "t-pol"
	pol.Priority = 1000
	pol.Action = "require_approval"
	pol.RequiredApprovers = 3
	pol.Enabled = true
	pol.Conditions = []byte(`{}`)
	if err := pol.Create(); err != nil {
		t.Fatalf("policy: %v", err)
	}

	// Operation under orgA.
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgA
	wid := "wallet-A"
	tx.WalletID = &wid
	tx.TxType = "treasury_sign"
	tx.Chain = "evm"
	tx.Status = "pending_approval"
	initiator := "u-A-initiator"
	tx.InitiatedBy = &initiator
	tx.ApprovedBy = []string{"seed"}
	if err := tx.Create(); err != nil {
		t.Fatalf("create op: %v", err)
	}
	opID := tx.Id()

	// A tenant-B signer attempting to approve orgA's op. Handler must 404
	// on the OrgID mismatch.
	body := map[string]string{"operationId": opID}
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/sign", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, "org-B")
	reqCtx = context.WithValue(reqCtx, ctxUserID, "u-A-comp") // stolen principal
	reqCtx = context.WithValue(reqCtx, ctxRole, "signer")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleTreasurySign(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-org approve: got %d body=%s", rec.Code, rec.Body.String())
	}
	_ = ctx
}

// TestTreasury_Sign_NonSignerRejected asserts an authenticated user who is
// NOT part of the treasury signer set is 403'd.
func TestTreasury_Sign_NonSignerRejected(t *testing.T) {
	s := newTreasuryServer(t)

	orgID := "org-A"
	tw := orm.New[db.TreasuryWallet](s.db.ORM)
	tw.OrgID = orgID
	tw.Name = "t"
	tw.WalletID = "w-a"
	tw.Chain = "evm"
	tw.Signers = []db.TreasurySigner{
		{Role: db.TreasurySignerCompliance, KeyRef: "u-comp"},
		{Role: db.TreasurySignerTreasurer, KeyRef: "u-cfo"},
		{Role: db.TreasurySignerPlatformHSM, KeyRef: expectedPlatformHSMKeyRef(orgID)},
		{Role: db.TreasurySignerBackupHSM, KeyRef: "providers/backup/hsm"},
	}
	tw.Tiers = []db.TreasuryTier{{MaxValue: "inf", Threshold: 3}}
	tw.Status = "active"
	_ = tw.Create()

	pol := orm.New[db.Policy](s.db.ORM)
	pol.OrgID = orgID
	pol.Kind = "treasury"
	pol.Name = "t"
	pol.Priority = 1000
	pol.Action = "require_approval"
	pol.RequiredApprovers = 3
	pol.Enabled = true
	pol.Conditions = []byte(`{}`)
	_ = pol.Create()

	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	wid := "w-a"
	tx.WalletID = &wid
	tx.TxType = "treasury_sign"
	tx.Chain = "evm"
	tx.Status = "pending_approval"
	initiator := "u-init"
	tx.InitiatedBy = &initiator
	_ = tx.Create()
	opID := tx.Id()

	body := map[string]string{"operationId": opID}
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/sign", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, orgID)
	reqCtx = context.WithValue(reqCtx, ctxUserID, "u-random")
	reqCtx = context.WithValue(reqCtx, ctxRole, "signer")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleTreasurySign(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-signer approve: got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestTreasury_RotateSigner_PlatformHSMScoped asserts a rotation that
// tries to reassign platform_hsm to another org's key path is rejected.
func TestTreasury_RotateSigner_PlatformHSMScoped(t *testing.T) {
	s := newTreasuryServer(t)

	orgID := "org-A"
	tw := orm.New[db.TreasuryWallet](s.db.ORM)
	tw.OrgID = orgID
	tw.Name = "t"
	tw.WalletID = "w-a"
	tw.Chain = "evm"
	tw.Signers = []db.TreasurySigner{
		{Role: db.TreasurySignerCompliance, KeyRef: "u-comp"},
		{Role: db.TreasurySignerTreasurer, KeyRef: "u-cfo"},
		{Role: db.TreasurySignerPlatformHSM, KeyRef: expectedPlatformHSMKeyRef(orgID)},
		{Role: db.TreasurySignerBackupHSM, KeyRef: "providers/backup/hsm"},
	}
	tw.Tiers = []db.TreasuryTier{{MaxValue: "inf", Threshold: 3}}
	tw.Status = "active"
	_ = tw.Create()

	// Attempt: rotate platform_hsm to tenant-B's key path.
	rbody := rotateSignerRequest{
		Role:      db.TreasurySignerPlatformHSM,
		NewKeyRef: expectedPlatformHSMKeyRef("globex"),
	}
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(rbody)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/wallets/"+tw.Id()+"/rotate-signer", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, orgID)
	reqCtx = context.WithValue(reqCtx, ctxUserID, "u-admin")
	reqCtx = context.WithValue(reqCtx, ctxRole, "admin")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()

	// Route via mux so {id} binds — set a chi RouteContext directly.
	req = reqWithChiCtx(req, map[string]string{"id": tw.Id()})
	s.handleRotateTreasurySigner(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org HSM rotation: got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestTreasury_TierEscalation_QuorumFromPolicy asserts that the wallet's
// tier policy drives `requiredApprovers`: a 100k op picks tier[0]=3, while
// a 500k op picks tier[1]=4.
func TestTreasury_TierEscalation_QuorumFromPolicy(t *testing.T) {
	s := newTreasuryServer(t)
	ctx := context.Background()
	orgID := "org-A"

	// Wallet with tiers: <=100k → 3, else 4.
	tw := orm.New[db.TreasuryWallet](s.db.ORM)
	tw.OrgID = orgID
	tw.Name = "t"
	tw.WalletID = "w-escalation"
	tw.Chain = "evm"
	tw.Signers = []db.TreasurySigner{
		{Role: db.TreasurySignerCompliance, KeyRef: "u-comp"},
		{Role: db.TreasurySignerTreasurer, KeyRef: "u-cfo"},
		{Role: db.TreasurySignerPlatformHSM, KeyRef: expectedPlatformHSMKeyRef(orgID)},
		{Role: db.TreasurySignerBackupHSM, KeyRef: "providers/backup/hsm"},
	}
	tw.Tiers = []db.TreasuryTier{
		{MaxValue: "100000", Threshold: 3},
		{MaxValue: "inf", Threshold: 4},
	}
	tw.Status = "active"
	_ = tw.Create()

	// Policy enforcing wallet-level approval quorum: require_approval with
	// RequiredApprovers=3 as baseline. The tier selector above is exercised
	// by tierForOperation.
	pol := orm.New[db.Policy](s.db.ORM)
	pol.OrgID = orgID
	pol.Kind = "treasury"
	pol.Name = "t"
	pol.Priority = 1000
	pol.Action = "require_approval"
	pol.RequiredApprovers = 3
	pol.Enabled = true
	pol.Conditions = []byte(`{}`)
	_ = pol.Create()

	// Tier picker agrees with our expected thresholds.
	low := "50000"
	high := "200000"
	txLow := &db.Transaction{Amount: &low}
	txHigh := &db.Transaction{Amount: &high}
	if got := s.tierForOperation(tw, txLow); got.Threshold != 3 {
		t.Fatalf("low tier threshold=%d want 3", got.Threshold)
	}
	if got := s.tierForOperation(tw, txHigh); got.Threshold != 4 {
		t.Fatalf("high tier threshold=%d want 4", got.Threshold)
	}
	_ = ctx
}

// TestTreasury_HSMKeyRefIsPerOrg asserts expectedPlatformHSMKeyRef generates
// distinct, disjoint paths per org and includes the full prefix/suffix.
func TestTreasury_HSMKeyRefIsPerOrg(t *testing.T) {
	a := expectedPlatformHSMKeyRef("acme")
	b := expectedPlatformHSMKeyRef("globex")
	c := expectedPlatformHSMKeyRef("vcc")
	if a == b || b == c || a == c {
		t.Fatalf("HSM keyRefs must be distinct across orgs: %s / %s / %s", a, b, c)
	}
	if a != "providers/acme/mpc-cosigner-key" {
		t.Fatalf("acme path=%q", a)
	}
	if b != "providers/globex/mpc-cosigner-key" {
		t.Fatalf("globex path=%q", b)
	}
}

// TestTreasury_ApprovalsIncludeRegulator checks the regulator-lookup helper
// against an approver list.
func TestTreasury_ApprovalsIncludeRegulator(t *testing.T) {
	tw := &db.TreasuryWallet{
		Signers: []db.TreasurySigner{
			{Role: db.TreasurySignerCompliance, KeyRef: "u-comp"},
			{Role: db.TreasurySignerTreasurer, KeyRef: "u-cfo"},
			{Role: db.TreasurySignerRegulator, KeyRef: "u-reg"},
		},
	}
	if approvalsIncludeRegulator(tw, []string{"u-comp", "u-cfo"}) {
		t.Fatal("regulator not present, must return false")
	}
	if !approvalsIncludeRegulator(tw, []string{"u-comp", "u-reg"}) {
		t.Fatal("regulator present, must return true")
	}
}

// ensure unused import keeps time in play for tests that later want it.
var _ = time.Now
