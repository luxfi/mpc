package scheduler

import (
	"errors"
	"testing"
)

// canonical policy used across the truth table — model confidentiality
// over private lane on attested CPU + GPU.
var privatePolicy = WorkloadPolicy{
	WorkloadID:                  "model-private",
	MinTrust:                    TrustGPU,
	MinIO:                       IOPrivateLane,
	RequireModelConfidentiality: true,
	RequireGPUAttested:          true,
	RequireCPUAttested:          true,
	ApprovedKernelRoots:         [][32]byte{{1, 2, 3}, {4, 5, 6}},
}

func okWorker() Worker {
	return Worker{
		ID:                 "node-1",
		TrustMode:          TrustGPU,
		IOLevel:            IOPrivateLane,
		KernelManifestRoot: [32]byte{1, 2, 3},
		GPUAttested:        true,
		CPUAttested:        true,
		Online:             true,
	}
}

func TestEligible_TruthTable(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Worker)
		wantErr bool
		match   string
	}{
		{"happy path", func(w *Worker) {}, false, ""},
		{"offline", func(w *Worker) { w.Online = false }, true, "offline"},
		{"trust below floor", func(w *Worker) { w.TrustMode = TrustCVM }, true, "trust"},
		{"io below floor", func(w *Worker) { w.IOLevel = IOPrivateNet }, true, "io"},
		{"gpu unattested", func(w *Worker) { w.GPUAttested = false }, true, "GPU attestation"},
		{"cpu unattested", func(w *Worker) { w.CPUAttested = false }, true, "CPU attestation"},
		{"kernel root not approved", func(w *Worker) { w.KernelManifestRoot = [32]byte{99} }, true, "KernelManifestRoot not in approved set"},
		{"kernel root second match", func(w *Worker) { w.KernelManifestRoot = [32]byte{4, 5, 6} }, false, ""},
		{"missing kernel root", func(w *Worker) { w.KernelManifestRoot = [32]byte{} }, true, "missing KernelManifestRoot"},
		{"missing ID", func(w *Worker) { w.ID = "" }, true, "missing ID"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := okWorker()
			tc.mutate(&w)
			err := privatePolicy.Eligible(w)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.match)
				}
				if tc.match != "" && !contains(err.Error(), tc.match) {
					t.Fatalf("expected %q in error, got %q", tc.match, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
		})
	}
}

func TestEligible_NilPolicy(t *testing.T) {
	var p *WorkloadPolicy
	if err := p.Eligible(okWorker()); err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func TestEligible_PublicWorkloadAcceptsBareMetal(t *testing.T) {
	publicPolicy := WorkloadPolicy{
		WorkloadID: "public",
		MinTrust:   TrustNone,
		MinIO:      IOPublic,
	}
	w := Worker{ID: "n", Online: true}
	if err := publicPolicy.Eligible(w); err != nil {
		t.Fatalf("public workload should accept bare worker: %v", err)
	}
}

func TestEligible_ConfidentialityWithoutKernelRoots(t *testing.T) {
	p := WorkloadPolicy{
		WorkloadID:                  "broken",
		MinTrust:                    TrustGPU,
		MinIO:                       IOPrivateLane,
		RequireModelConfidentiality: true,
		RequireGPUAttested:          true,
		// no ApprovedKernelRoots — must reject
	}
	if err := p.Eligible(okWorker()); err == nil {
		t.Fatal("expected error when confidentiality required without approved roots")
	}
}

func TestStaticPolicySource(t *testing.T) {
	src := NewStaticPolicySource(map[string]*WorkloadPolicy{
		"a": &privatePolicy,
	})
	got, err := src.Lookup("a")
	if err != nil {
		t.Fatalf("lookup a: %v", err)
	}
	if got == nil || got.WorkloadID != "model-private" {
		t.Fatalf("got %+v", got)
	}
	if _, err := src.Lookup("missing"); err == nil {
		t.Fatal("expected error for missing workload")
	}
}

func TestScheduler_Eligible(t *testing.T) {
	src := NewStaticPolicySource(map[string]*WorkloadPolicy{"a": &privatePolicy})
	s := New(src)
	if err := s.Eligible(okWorker(), "a"); err != nil {
		t.Fatalf("happy: %v", err)
	}
	bad := okWorker()
	bad.TrustMode = TrustCVM
	if err := s.Eligible(bad, "a"); err == nil {
		t.Fatal("expected eligibility failure")
	}
	if err := s.Eligible(okWorker(), "missing"); err == nil {
		t.Fatal("expected lookup failure")
	}
}

func TestScheduler_AuthorizeSession_PrivateLaneRefusal(t *testing.T) {
	src := NewStaticPolicySource(map[string]*WorkloadPolicy{"a": &privatePolicy})
	s := New(src)

	good1 := okWorker()
	good1.ID = "n1"
	good2 := okWorker()
	good2.ID = "n2"
	bad := okWorker()
	bad.ID = "n3"
	bad.IOLevel = IOPublic // private-lane refusal: this worker MUST be excluded

	out, err := s.AuthorizeSession("a", []Worker{good1, bad, good2}, 2)
	if err != nil {
		t.Fatalf("expected 2 eligible: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 eligible, got %d", len(out))
	}
	for _, w := range out {
		if w.ID == "n3" {
			t.Fatalf("public-IO worker n3 leaked through gate")
		}
	}

	if _, err := s.AuthorizeSession("a", []Worker{bad}, 1); !errors.Is(err, ErrInsufficientTrust) {
		t.Fatalf("expected ErrInsufficientTrust, got %v", err)
	}
}

func TestScheduler_AuthorizeDrain(t *testing.T) {
	src := NewStaticPolicySource(map[string]*WorkloadPolicy{"a": &privatePolicy})
	s := New(src)

	w1 := okWorker()
	w1.ID = "n1"
	w2 := okWorker()
	w2.ID = "n2"
	w3 := okWorker()
	w3.ID = "n3"

	// drain n1 with 3 healthy → 2 remain → ok for threshold=2
	if err := s.AuthorizeDrain(DrainRequest{
		NodeID:     "n1",
		WorkloadID: "a",
		Workers:    []Worker{w1, w2, w3},
		Threshold:  2,
	}); err != nil {
		t.Fatalf("happy drain: %v", err)
	}

	// drain n1 with 3 healthy → 2 remain → fail for threshold=3
	err := s.AuthorizeDrain(DrainRequest{
		NodeID:     "n1",
		WorkloadID: "a",
		Workers:    []Worker{w1, w2, w3},
		Threshold:  3,
	})
	if !errors.Is(err, ErrInsufficientTrust) {
		t.Fatalf("expected ErrInsufficientTrust, got %v", err)
	}

	// pre-existing ineligible worker doesn't count toward remaining
	w3bad := w3
	w3bad.GPUAttested = false
	err = s.AuthorizeDrain(DrainRequest{
		NodeID:     "n1",
		WorkloadID: "a",
		Workers:    []Worker{w1, w2, w3bad},
		Threshold:  2,
	})
	if !errors.Is(err, ErrInsufficientTrust) {
		t.Fatalf("expected ErrInsufficientTrust when only 1 eligible remains, got %v", err)
	}

	// missing workload
	err = s.AuthorizeDrain(DrainRequest{
		NodeID:     "n1",
		WorkloadID: "missing",
		Workers:    []Worker{w1, w2},
		Threshold:  1,
	})
	if err == nil || errors.Is(err, ErrInsufficientTrust) {
		t.Fatalf("expected lookup error, got %v", err)
	}
}

func TestNew_NilSourcePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	New(nil)
}

// contains is a tiny strings.Contains shim to keep test deps minimal.
func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
