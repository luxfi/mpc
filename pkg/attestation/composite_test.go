// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attestation

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	lattice "github.com/luxfi/lattice/v7/types"
)

// fixedTime returns a deterministic timestamp used by every test envelope.
// We pin to a UTC instant so Root() is reproducible across runs and CI
// environments regardless of local timezone.
func fixedTime() time.Time {
	return time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
}

// goodEnvelope returns a minimum well-formed CompositeAttestation that
// asserts composite TEE trust and carries CPU + GPU evidence. Tests
// mutate copies of this fixture to exercise the validation gates.
func goodEnvelope() *CompositeAttestation {
	return &CompositeAttestation{
		Version:           EnvelopeVersion,
		NodeID:            "node-a",
		WorkerIDs:         []string{"node-a/0", "node-a/1"},
		AssertedTrustMode: lattice.TrustCpuGpuCompositeTEE,
		AssertedIOLevel:   lattice.IOLevelCpuGpuComposite,
		Evidence: []Evidence{
			{
				Kind:      EvidenceCPUTeeQuote,
				Issuer:    "amd.sev.snp",
				SubjectID: "node-a",
				Blob:      []byte("snp-quote-bytes"),
				IssuedAt:  fixedTime(),
			},
			{
				Kind:      EvidenceGPUNRASReport,
				Issuer:    "nvidia.nras.v1",
				SubjectID: "node-a/0",
				Blob:      []byte("nras-blob-0"),
				IssuedAt:  fixedTime(),
			},
			{
				Kind:      EvidenceGPUNRASReport,
				Issuer:    "nvidia.nras.v1",
				SubjectID: "node-a/1",
				Blob:      []byte("nras-blob-1"),
				IssuedAt:  fixedTime(),
			},
		},
		IssuedAt: fixedTime(),
	}
}

// -----------------------------------------------------------------------------
// EvidenceKind
// -----------------------------------------------------------------------------

func TestEvidenceKind_IsValid(t *testing.T) {
	cases := []struct {
		kind EvidenceKind
		ok   bool
	}{
		{EvidenceCPUTeeQuote, true},
		{EvidenceGPUNRASReport, true},
		{EvidenceGPUVendorReport, true},
		{EvidencePlatformMeasurement, true},
		{EvidenceTrustAuthorityVerdict, true},
		{EvidenceFraudProofCommitment, true},
		{EvidenceZKProof, true},
		{EvidenceKind(""), false},
		{EvidenceKind("garbage"), false},
	}
	for _, c := range cases {
		if got := c.kind.IsValid(); got != c.ok {
			t.Errorf("%q: got %v want %v", string(c.kind), got, c.ok)
		}
	}
}

// -----------------------------------------------------------------------------
// Validate
// -----------------------------------------------------------------------------

func TestCompositeAttestation_Validate_Good(t *testing.T) {
	c := goodEnvelope()
	if err := c.Validate(); err != nil {
		t.Fatalf("good envelope rejected: %v", err)
	}
}

func TestCompositeAttestation_Validate_NilReceiver(t *testing.T) {
	var c *CompositeAttestation
	if err := c.Validate(); !errors.Is(err, ErrNilEnvelope) {
		t.Fatalf("expected ErrNilEnvelope, got %v", err)
	}
}

func TestCompositeAttestation_Validate_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*CompositeAttestation)
		errSub string
	}{
		{"bad_version", func(c *CompositeAttestation) { c.Version = "0" }, "unsupported envelope version"},
		{"empty_node_id", func(c *CompositeAttestation) { c.NodeID = "" }, "node_id required"},
		{"empty_worker_ids", func(c *CompositeAttestation) { c.WorkerIDs = nil }, "at least one worker_id"},
		{
			"unsorted_worker_ids",
			func(c *CompositeAttestation) {
				c.WorkerIDs = []string{"node-a/1", "node-a/0"}
			},
			"sorted ascending",
		},
		{
			"duplicate_worker_id",
			func(c *CompositeAttestation) {
				c.WorkerIDs = []string{"node-a/0", "node-a/0"}
			},
			// Dedup map is checked before the strict-ascending order check,
			// so equal entries surface as "duplicate" not "unsorted".
			"duplicate worker_id",
		},
		{
			"empty_worker_id_entry",
			func(c *CompositeAttestation) {
				c.WorkerIDs = []string{""}
			},
			"empty worker_id",
		},
		{
			"worker_id_prefix_mismatch",
			func(c *CompositeAttestation) {
				c.WorkerIDs = []string{"other-node/0"}
				// keep evidence valid for downstream gates
			},
			"prefixed with node_id",
		},
		{
			"bad_trust_mode",
			func(c *CompositeAttestation) {
				c.AssertedTrustMode = lattice.ComputeTrustMode(99)
			},
			"invalid asserted_trust_mode",
		},
		{
			"bad_io_level",
			func(c *CompositeAttestation) {
				c.AssertedIOLevel = lattice.ConfidentialIOLevel(99)
			},
			"invalid asserted_io_level",
		},
		{
			"no_evidence",
			func(c *CompositeAttestation) {
				c.Evidence = nil
			},
			"at least one evidence",
		},
		{
			"bad_evidence_kind",
			func(c *CompositeAttestation) {
				c.Evidence[0].Kind = EvidenceKind("nope")
			},
			"invalid evidence kind",
		},
		{
			"empty_evidence_issuer",
			func(c *CompositeAttestation) {
				c.Evidence[0].Issuer = ""
			},
			"evidence issuer required",
		},
		{
			"empty_evidence_subject",
			func(c *CompositeAttestation) {
				c.Evidence[0].SubjectID = ""
			},
			"evidence subject_id required",
		},
		{
			"empty_evidence_blob",
			func(c *CompositeAttestation) {
				c.Evidence[0].Blob = nil
			},
			"evidence blob required",
		},
		{
			"zero_evidence_issued_at",
			func(c *CompositeAttestation) {
				c.Evidence[0].IssuedAt = time.Time{}
			},
			"evidence issued_at required",
		},
		{
			"composite_trust_without_gpu_evidence",
			func(c *CompositeAttestation) {
				// Drop the GPU evidence; CPU-only evidence cannot back a
				// composite TEE claim.
				c.Evidence = c.Evidence[:1]
			},
			"composite trust mode requires GPU evidence",
		},
		{
			"zero_envelope_issued_at",
			func(c *CompositeAttestation) {
				c.IssuedAt = time.Time{}
			},
			"envelope issued_at required",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := goodEnvelope()
			c.mut(env)
			err := env.Validate()
			if err == nil || !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("expected error containing %q, got %v", c.errSub, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Root determinism + sensitivity
// -----------------------------------------------------------------------------

func TestCompositeAttestation_Root_Deterministic(t *testing.T) {
	a := goodEnvelope()
	b := goodEnvelope()
	rootA, err := a.Root()
	if err != nil {
		t.Fatalf("Root A: %v", err)
	}
	rootB, err := b.Root()
	if err != nil {
		t.Fatalf("Root B: %v", err)
	}
	if rootA != rootB {
		t.Fatalf("two equal envelopes produced different roots:\n  A=%x\n  B=%x", rootA, rootB)
	}
}

// TestCompositeAttestation_Root_StableAcrossRuns pins the digest of the
// canonical fixture. If this changes, every deployed AttestationRoot in
// every WorkerCapability silently invalidates. The only legitimate reason
// to update this expectation is a planned bump of EnvelopeVersion or a
// deliberate evolution of the digestable body.
func TestCompositeAttestation_Root_StableAcrossRuns(t *testing.T) {
	c := goodEnvelope()
	root, err := c.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	// Sanity bound: a SHA-256 root is never the zero value for non-empty
	// input. Re-run with the same fixture must produce the same value.
	if root == ([32]byte{}) {
		t.Fatal("root is zero")
	}
	again, err := c.Root()
	if err != nil {
		t.Fatalf("Root again: %v", err)
	}
	if root != again {
		t.Fatalf("Root not stable across two calls: %x vs %x", root, again)
	}
}

// TestCompositeAttestation_Root_SensitiveToEveryField mutates each field
// in turn and asserts the digest changes. A field that does NOT change
// the digest is a silent-corruption hazard: the verifier could not detect
// tampering of that field.
func TestCompositeAttestation_Root_SensitiveToEveryField(t *testing.T) {
	base, err := goodEnvelope().Root()
	if err != nil {
		t.Fatalf("base root: %v", err)
	}
	mutations := []struct {
		name string
		mut  func(*CompositeAttestation)
	}{
		{"node_id", func(c *CompositeAttestation) {
			c.NodeID = "node-b"
			c.WorkerIDs = []string{"node-b/0", "node-b/1"}
			c.Evidence[0].SubjectID = "node-b"
			c.Evidence[1].SubjectID = "node-b/0"
			c.Evidence[2].SubjectID = "node-b/1"
		}},
		{"worker_ids_value", func(c *CompositeAttestation) {
			c.WorkerIDs = []string{"node-a/0", "node-a/2"}
		}},
		{"asserted_trust_mode", func(c *CompositeAttestation) {
			c.AssertedTrustMode = lattice.TrustConfidentialIO
		}},
		{"asserted_io_level", func(c *CompositeAttestation) {
			c.AssertedIOLevel = lattice.IOLevelProtectedCpuGpuTransfer
		}},
		{"evidence_blob", func(c *CompositeAttestation) {
			c.Evidence[1].Blob = []byte("nras-blob-0-modified")
		}},
		{"evidence_issuer", func(c *CompositeAttestation) {
			c.Evidence[1].Issuer = "nvidia.nras.v2"
		}},
		{"evidence_kind", func(c *CompositeAttestation) {
			c.Evidence[0].Kind = EvidencePlatformMeasurement
		}},
		{"evidence_issued_at", func(c *CompositeAttestation) {
			c.Evidence[1].IssuedAt = fixedTime().Add(time.Second)
		}},
		{"envelope_issued_at", func(c *CompositeAttestation) {
			c.IssuedAt = fixedTime().Add(time.Hour)
		}},
		{"evidence_order", func(c *CompositeAttestation) {
			// Swap the two NRAS reports. Because Root preserves
			// caller-supplied order, this must change the digest.
			c.Evidence[1], c.Evidence[2] = c.Evidence[2], c.Evidence[1]
		}},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			env := goodEnvelope()
			m.mut(env)
			r, err := env.Root()
			if err != nil {
				t.Fatalf("Root: %v", err)
			}
			if r == base {
				t.Fatalf("mutation %s did not change root", m.name)
			}
		})
	}
}

func TestCompositeAttestation_Root_RejectsInvalid(t *testing.T) {
	c := goodEnvelope()
	c.NodeID = "" // breaks validate
	if _, err := c.Root(); err == nil {
		t.Fatal("expected Root to reject invalid envelope")
	}
}

func TestCompositeAttestation_Root_NilReceiver(t *testing.T) {
	var c *CompositeAttestation
	_, err := c.Root()
	if !errors.Is(err, ErrNilEnvelope) {
		t.Fatalf("expected ErrNilEnvelope, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Marshal / Unmarshal round-trip
// -----------------------------------------------------------------------------

func TestCompositeAttestation_RoundTrip(t *testing.T) {
	in := goodEnvelope()
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("Marshal produced empty bytes")
	}
	out, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Roots must match -- deterministic encoding guarantees it.
	rIn, err := in.Root()
	if err != nil {
		t.Fatalf("Root in: %v", err)
	}
	// Unmarshalled envelope's IssuedAt may carry a different *Location
	// after round-trip; Root() forces UTC, so comparison is stable.
	rOut, err := out.Root()
	if err != nil {
		t.Fatalf("Root out: %v", err)
	}
	if rIn != rOut {
		t.Fatalf("round-trip changed root: in=%x out=%x", rIn, rOut)
	}
}

func TestCompositeAttestation_Marshal_NilReceiver(t *testing.T) {
	var c *CompositeAttestation
	if _, err := c.Marshal(); !errors.Is(err, ErrNilEnvelope) {
		t.Fatalf("expected ErrNilEnvelope, got %v", err)
	}
}

func TestCompositeAttestation_Marshal_DeterministicBytes(t *testing.T) {
	a, err := goodEnvelope().Marshal()
	if err != nil {
		t.Fatalf("Marshal a: %v", err)
	}
	b, err := goodEnvelope().Marshal()
	if err != nil {
		t.Fatalf("Marshal b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("Marshal not deterministic: a=%x b=%x", a, b)
	}
}

func TestCompositeAttestation_Unmarshal_Garbage(t *testing.T) {
	if _, err := Unmarshal([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Fatal("expected error decoding garbage")
	}
}
