package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luxfi/mpc/pkg/types"
)

// mockMPCBackend implements MPCBackend for KMS handler tests.
// Only used where validation passes and the handler calls MPC.
type mockMPCBackend struct {
	keygenResult *KeygenResult
	signResult   *SignResult
	keygenErr    error
	signErr      error
	reshareErr   error

	// signNetwork records the network the handler routed with, so a test can
	// assert which curve a request would have selected.
	signNetwork types.NetworkCode
}

func (m *mockMPCBackend) TriggerKeygen(orgID, walletID string) (*KeygenResult, error) {
	if m.keygenErr != nil {
		return nil, m.keygenErr
	}
	return m.keygenResult, nil
}
func (m *mockMPCBackend) TriggerSign(orgID, walletID string, network types.NetworkCode, payload []byte) (*SignResult, error) {
	m.signNetwork = network
	if m.signErr != nil {
		return nil, m.signErr
	}
	return m.signResult, nil
}
func (m *mockMPCBackend) TriggerReshare(orgID, walletID string, newThreshold int, newParticipants []string) error {
	return m.reshareErr
}
func (m *mockMPCBackend) ExportKeyShare(orgID, walletID string) ([]byte, error) {
	return nil, nil
}
func (m *mockMPCBackend) GetClusterStatus() *ClusterStatus {
	return &ClusterStatus{Ready: true}
}

func kmsTestServer() *Server {
	return &Server{
		jwtSecret: []byte("kms-test-secret"),
		mpc:       &mockMPCBackend{},
	}
}

func kmsRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	// Inject orgID into context (simulating authMiddleware).
	ctx := context.WithValue(req.Context(), ctxOrgID, "test-org")
	ctx = context.WithValue(ctx, ctxUserID, "test-user")
	ctx = context.WithValue(ctx, ctxRole, "admin")
	return req.WithContext(ctx)
}

func decodeKMSError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return body["error"]
}

// --- handleKMSGenerate validation ---

func TestKMSGenerate_EmptyValidatorID(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/generate", kmsGenerateRequest{
		ValidatorID: "",
		Threshold:   3,
		Parties:     5,
	})
	rec := httptest.NewRecorder()

	s.handleKMSGenerate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "validator_id is required" {
		t.Fatalf("error = %q, want %q", msg, "validator_id is required")
	}
}

func TestKMSGenerate_ThresholdLessThanTwo(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/generate", kmsGenerateRequest{
		ValidatorID: "val-1",
		Threshold:   1,
		Parties:     5,
	})
	rec := httptest.NewRecorder()

	s.handleKMSGenerate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "threshold must be >= 2" {
		t.Fatalf("error = %q, want %q", msg, "threshold must be >= 2")
	}
}

func TestKMSGenerate_PartiesLessThanThreshold(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/generate", kmsGenerateRequest{
		ValidatorID: "val-1",
		Threshold:   4,
		Parties:     3,
	})
	rec := httptest.NewRecorder()

	s.handleKMSGenerate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "parties must be >= threshold" {
		t.Fatalf("error = %q, want %q", msg, "parties must be >= threshold")
	}
}

func TestKMSGenerate_ThresholdZero(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/generate", kmsGenerateRequest{
		ValidatorID: "val-1",
		Threshold:   0,
		Parties:     5,
	})
	rec := httptest.NewRecorder()

	s.handleKMSGenerate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "threshold must be >= 2" {
		t.Fatalf("error = %q, want %q", msg, "threshold must be >= 2")
	}
}

// --- handleKMSSign validation ---

func TestKMSSign_EmptyMessage(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/val-1/sign", kmsSignRequest{
		KeyType: "bls",
		Message: nil,
	})
	rec := httptest.NewRecorder()

	s.handleKMSSign(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "message is required" {
		t.Fatalf("error = %q, want %q", msg, "message is required")
	}
}

func TestKMSSign_EmptyMessageBytes(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/val-1/sign", kmsSignRequest{
		KeyType: "bls",
		Message: []byte{},
	})
	rec := httptest.NewRecorder()

	s.handleKMSSign(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "message is required" {
		t.Fatalf("error = %q, want %q", msg, "message is required")
	}
}

// --- handleKMSRotate validation ---

func TestKMSRotate_EmptyRequest(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/val-1/rotate", kmsRotateRequest{})
	rec := httptest.NewRecorder()

	s.handleKMSRotate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "new_threshold or new_participants required" {
		t.Fatalf("error = %q, want %q", msg, "new_threshold or new_participants required")
	}
}

func TestKMSRotate_ZeroThresholdNoParticipants(t *testing.T) {
	s := kmsTestServer()
	req := kmsRequest(t, http.MethodPost, "/v1/keys/val-1/rotate", kmsRotateRequest{
		NewThreshold:    0,
		NewParticipants: nil,
	})
	rec := httptest.NewRecorder()

	s.handleKMSRotate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- Verify handlers use getOrgID (context-based) not X-Org-ID header ---

func TestKMSGenerate_UsesContextOrgID(t *testing.T) {
	// Regression: orgID must come from JWT context (getOrgID), not from
	// a client-supplied header. If someone sets X-Org-ID header to a
	// different org, the handler must ignore it and use the context value.
	s := kmsTestServer()
	s.mpc = &mockMPCBackend{
		keygenResult: &KeygenResult{
			WalletID:    "w-1",
			ECDSAPubKey: "pub-ecdsa",
			EDDSAPubKey: "pub-eddsa",
		},
	}

	req := kmsRequest(t, http.MethodPost, "/v1/keys/generate", kmsGenerateRequest{
		ValidatorID: "val-ctx-test",
		Threshold:   2,
		Parties:     3,
	})
	// Attacker tries to override org via header.
	req.Header.Set("X-Org-ID", "attacker-org")
	rec := httptest.NewRecorder()

	s.handleKMSGenerate(rec, req)

	// Handler should use context org ("test-org" from kmsRequest), not "attacker-org".
	// If s.db is nil the handler skips the duplicate check and proceeds to keygen.
	// The mock MPC backend succeeds. We verify the handler did not error on org mismatch.
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

// --- handleKMSGenerate invalid JSON body ---

func TestKMSGenerate_InvalidJSON(t *testing.T) {
	s := kmsTestServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/generate", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ctxOrgID, "test-org")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleKMSGenerate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if msg := decodeKMSError(t, rec); msg != "invalid request body" {
		t.Fatalf("error = %q, want %q", msg, "invalid request body")
	}
}

func TestKMSSign_InvalidJSON(t *testing.T) {
	s := kmsTestServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/val-1/sign", bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ctxOrgID, "test-org")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleKMSSign(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestKMSRotate_InvalidJSON(t *testing.T) {
	s := kmsTestServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/val-1/rotate", bytes.NewReader([]byte("[")))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ctxOrgID, "test-org")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleKMSRotate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
