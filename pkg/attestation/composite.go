// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Package attestation defines the composite attestation envelope that the
// Lux GPU Runtime uses to bind worker capability records to verifiable
// hardware evidence. A CompositeAttestation aggregates evidence from
// multiple roots of trust:
//
//   - CPU TEE quote (AMD SEV-SNP, Intel TDX, ARM CCA, ...)
//   - GPU attestation report (NVIDIA NRAS for Hopper / Blackwell, AMD
//     equivalents when published)
//   - Platform / firmware measurements (UEFI, kernel, microcode)
//   - Optional verifier-specific evidence (Intel Trust Authority verdict,
//     NRAS device-state report, fraud-proof commitment, ZK proof)
//
// The Root() method returns the SHA-256 of the deterministically encoded
// envelope. That root is what:
//
//   - the worker stores in WorkerCapability.AttestationRoot
//   - the scheduler logs and indexes
//   - downstream verifiers re-derive locally to detect tampering
//
// Determinism is RFC 8949 §4.2 Core Deterministic CBOR via fxamacker/cbor.
// We chose CBOR (not custom binary) because the off-chain composite
// attestation envelope shape is the de-facto standard used by NVIDIA NRAS
// and Intel Trust Authority output, and because mpc already uses CBOR for
// the canonical-intent + FROST/LSS config marshalers (see
// pkg/intent/canonical.go::Digest). One library, one canonical encoding.
//
// References:
//
//   - LP-137-TRUST-REGISTRY.md
//   - NVIDIA Remote Attestation Service (NRAS) report v1, 2024
//   - NVIDIA Confidential Compute Whitepaper, Hopper / Blackwell
//   - Intel Trust Authority composite attestation specification, 2024
//   - RFC 8949 (CBOR), RFC 9090 (CBOR Tags)
package attestation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	lattice "github.com/luxfi/lattice/v7/types"
	"github.com/luxfi/cc/attest"
)

// EnvelopeVersion is the schema version of the CompositeAttestation
// envelope. Bump only on breaking changes; old envelopes never silently
// match new ones because the version field participates in the digest.
const EnvelopeVersion = "1"

// EvidenceKind identifies the source of a single evidence blob inside the
// envelope. Stable string values are part of the wire / log contract.
type EvidenceKind string

const (
	// EvidenceCPUTeeQuote: a CPU TEE quote (SEV-SNP AttestationReport,
	// Intel TDX TDREPORT, ARM CCA report). Carried opaquely; the verifier
	// re-validates against the vendor's verification service.
	EvidenceCPUTeeQuote EvidenceKind = "cpu_tee_quote"

	// EvidenceGPUNRASReport: a NVIDIA NRAS device-state report for one
	// GPU. One blob per GPU; multi-GPU nodes carry one entry per device.
	EvidenceGPUNRASReport EvidenceKind = "gpu_nras_report"

	// EvidenceGPUVendorReport: a non-NVIDIA GPU attestation blob (AMD,
	// Intel). Reserved for when these vendors publish equivalents.
	EvidenceGPUVendorReport EvidenceKind = "gpu_vendor_report"

	// EvidencePlatformMeasurement: UEFI / kernel / microcode measurement
	// log. One per node, not per worker.
	EvidencePlatformMeasurement EvidenceKind = "platform_measurement"

	// EvidenceTrustAuthorityVerdict: Intel Trust Authority verdict over
	// the composite quote. Optional; presence + verdict-pass are enforced
	// by the verifier, not by this package.
	EvidenceTrustAuthorityVerdict EvidenceKind = "trust_authority_verdict"

	// EvidenceFraudProofCommitment: a fraud-proof commitment hash for
	// verifiable-compute lanes (LP-025).
	EvidenceFraudProofCommitment EvidenceKind = "fraud_proof_commitment"

	// EvidenceZKProof: a zero-knowledge proof of correct execution
	// (LP-013 §ZK). The proof bytes themselves; the verifier holds the
	// matching verification key.
	EvidenceZKProof EvidenceKind = "zk_proof"
)

// IsValid reports whether k is one of the defined evidence kinds.
func (k EvidenceKind) IsValid() bool {
	switch k {
	case EvidenceCPUTeeQuote, EvidenceGPUNRASReport, EvidenceGPUVendorReport,
		EvidencePlatformMeasurement, EvidenceTrustAuthorityVerdict,
		EvidenceFraudProofCommitment, EvidenceZKProof:
		return true
	}
	return false
}

// Evidence is one entry inside a CompositeAttestation. The Blob is opaque
// from this package's perspective: the consumer (a verifier specific to
// the Kind) is responsible for parsing and validating.
type Evidence struct {
	// Kind tags the source of the blob.
	Kind EvidenceKind `cbor:"kind"`

	// Issuer is the canonical issuer identifier for this evidence
	// (e.g. "nvidia.nras.v1", "amd.sev.snp", "intel.tdx", "intel.ta.v1").
	// Used by the verifier to dispatch to the correct validator.
	Issuer string `cbor:"issuer"`

	// SubjectID identifies the entity the evidence is *about*: a
	// WorkerID for GPU evidence, a NodeID for platform / CPU evidence.
	SubjectID string `cbor:"subject_id"`

	// Blob is the raw evidence bytes. Treated opaquely by Root(); the
	// blob's bytes participate in the digest, so any tampering changes
	// the root.
	Blob []byte `cbor:"blob"`

	// IssuedAt is when the issuer produced this evidence (their wall
	// clock). Recorded for audit; not validated by this package.
	IssuedAt time.Time `cbor:"issued_at"`
}

// CompositeAttestation aggregates per-worker evidence into a single
// envelope whose digest is the canonical attestation root. The struct is
// the wire form: every field participates in Root() except where noted.
type CompositeAttestation struct {
	// Version is the envelope schema version.
	Version string `cbor:"version"`

	// NodeID is the node this attestation is rooted at.
	NodeID string `cbor:"node_id"`

	// WorkerIDs are the worker endpoints covered by this envelope. Sorted
	// ascending, deduplicated. The marshaler does NOT sort for you;
	// callers must produce a stable order.
	WorkerIDs []string `cbor:"worker_ids"`

	// AssertedTrustMode + AssertedIOLevel are the *claimed* guarantees
	// the worker is publishing alongside this attestation. The verifier
	// checks that the evidence supports the claim before accepting.
	AssertedTrustMode lattice.ComputeTrustMode    `cbor:"asserted_trust_mode"`
	AssertedIOLevel   lattice.ConfidentialIOLevel `cbor:"asserted_io_level"`

	// Evidence is the unordered set of evidence blobs. The Root()
	// computation does NOT re-sort; it preserves caller-supplied order
	// because evidence blobs may have ordering semantics the verifier
	// depends on (e.g. measurement-log ordering).
	Evidence []Evidence `cbor:"evidence"`

	// IssuedAt is the worker's wall-clock time when the envelope was
	// produced. Bound to the digest so a replay of an old envelope is
	// detectable as soon as the verifier knows the freshness window.
	IssuedAt time.Time `cbor:"issued_at"`
}

// detEnc is the singleton deterministic CBOR encoder used by Root() and
// Marshal(). cbor.EncMode is goroutine-safe.
var detEnc cbor.EncMode

func init() {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		// CoreDetEncOptions() is constant-derived; this can never fail.
		// Panic at init so the bug surfaces before any worker tries to
		// publish an attestation.
		panic("attestation: cbor.CoreDetEncOptions().EncMode() failed: " + err.Error())
	}
	detEnc = enc
}

// Root returns the SHA-256 of the deterministic CBOR encoding of the
// envelope. The same envelope produces the same root on every node, every
// run -- this is the value stored in WorkerCapability.AttestationRoot and
// indexed by the scheduler.
//
// Root does NOT verify the evidence. It is purely a deterministic digest.
// Verification is done by the consumer of the root, not by the producer.
func (c *CompositeAttestation) Root() ([32]byte, error) {
	if c == nil {
		return [32]byte{}, ErrNilEnvelope
	}
	if err := c.validate(); err != nil {
		return [32]byte{}, err
	}
	body := envelopeBody{
		Version:           c.Version,
		NodeID:            c.NodeID,
		WorkerIDs:         c.WorkerIDs,
		AssertedTrustMode: c.AssertedTrustMode,
		AssertedIOLevel:   c.AssertedIOLevel,
		Evidence:          c.Evidence,
		IssuedAt:          c.IssuedAt.UTC(),
	}
	enc, err := detEnc.Marshal(body)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(enc), nil
}

// Marshal serializes the envelope using the same deterministic encoder
// used by Root. The wire bytes are byte-stable across runs and platforms.
func (c *CompositeAttestation) Marshal() ([]byte, error) {
	if c == nil {
		return nil, ErrNilEnvelope
	}
	return detEnc.Marshal(c)
}

// Unmarshal restores a CompositeAttestation from its CBOR bytes.
func Unmarshal(b []byte) (*CompositeAttestation, error) {
	var c CompositeAttestation
	if err := cbor.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate reports whether the envelope is structurally well-formed. It
// does NOT verify any cryptographic property of the evidence -- that is
// the verifier's job and depends on per-issuer logic.
func (c *CompositeAttestation) Validate() error {
	if c == nil {
		return ErrNilEnvelope
	}
	return c.validate()
}

// validate is the unexported version used by Root(); duplicated only so
// callers of Root() get the same checks without an extra explicit call.
func (c *CompositeAttestation) validate() error {
	if c.Version != EnvelopeVersion {
		return errors.New("attestation: unsupported envelope version")
	}
	if c.NodeID == "" {
		return errors.New("attestation: node_id required")
	}
	if len(c.WorkerIDs) == 0 {
		return errors.New("attestation: at least one worker_id required")
	}
	seen := make(map[string]struct{}, len(c.WorkerIDs))
	for i, wid := range c.WorkerIDs {
		if wid == "" {
			return errors.New("attestation: empty worker_id")
		}
		if !strings.HasPrefix(wid, c.NodeID+"/") {
			return errors.New("attestation: worker_id must be prefixed with node_id/")
		}
		if _, dup := seen[wid]; dup {
			return errors.New("attestation: duplicate worker_id")
		}
		seen[wid] = struct{}{}
		if i > 0 && c.WorkerIDs[i-1] >= wid {
			return errors.New("attestation: worker_ids must be sorted ascending")
		}
	}
	if !c.AssertedTrustMode.Valid() {
		return errors.New("attestation: invalid asserted_trust_mode")
	}
	if !c.AssertedIOLevel.Valid() {
		return errors.New("attestation: invalid asserted_io_level")
	}
	if len(c.Evidence) == 0 {
		return errors.New("attestation: at least one evidence required")
	}
	for i := range c.Evidence {
		ev := &c.Evidence[i]
		if !ev.Kind.IsValid() {
			return errors.New("attestation: invalid evidence kind")
		}
		if ev.Issuer == "" {
			return errors.New("attestation: evidence issuer required")
		}
		if ev.SubjectID == "" {
			return errors.New("attestation: evidence subject_id required")
		}
		if len(ev.Blob) == 0 {
			return errors.New("attestation: evidence blob required")
		}
		if ev.IssuedAt.IsZero() {
			return errors.New("attestation: evidence issued_at required")
		}
	}
	if c.AssertedTrustMode >= lattice.TrustCpuGpuCompositeTEE && !hasGPUEvidence(c.Evidence) {
		return errors.New("attestation: composite trust mode requires GPU evidence")
	}
	if c.IssuedAt.IsZero() {
		return errors.New("attestation: envelope issued_at required")
	}
	return nil
}

// VerifyEvidence cryptographically verifies every CPU TEE / GPU evidence
// blob in the envelope using cc/attest. This is the wire-in point for
// the canonical verifier: callers MUST invoke VerifyEvidence (or a
// direct call into cc/attest.Dispatch) before trusting any
// MEASUREMENT, REPORT_DATA, or HOST_DATA value the C-ABI parser
// exposed. Validate() must succeed first; this method assumes
// structural integrity.
//
// Behaviour by issuer:
//
//   - "amd.sev.snp"    → cc/attest.SEVSNP{}  (PRODUCTION)
//   - "intel.tdx"      → cc/attest.TDX{}     (ErrNotImplemented; #222 stage 2)
//   - "nvidia.nras.v1" → cc/attest.NVTrust{} (PRODUCTION local-RIM verify;
//     supply the signed RIM + trust roots via attest.WithNVTrustRIM /
//     attest.WithNVTrustTrustRoots in the AttestOptions)
//   - other issuers    → out[i] is nil (no verifier registered yet)
//
// The returned slice has the same length and order as c.Evidence;
// callers map verified[i] back to c.Evidence[i] by index. On any
// cryptographic failure VerifyEvidence returns (nil, err) and the
// caller MUST refuse the originating request.
func (c *CompositeAttestation) VerifyEvidence(ctx context.Context, opts ...attest.Option) ([]*attest.VerifiedReport, error) {
	if c == nil {
		return nil, ErrNilEnvelope
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	out := make([]*attest.VerifiedReport, len(c.Evidence))
	for i := range c.Evidence {
		ev := &c.Evidence[i]
		kind, ok := evidenceKindForIssuer(ev.Issuer)
		if !ok {
			// Issuer has no registered cc/attest verifier yet; leave
			// out[i] nil. Callers asserting composite trust must
			// enforce that all expected issuers have non-nil verified
			// reports — see kms release-gate policy.
			continue
		}
		rep, err := attest.Dispatch(ctx, kind, ev.Blob, opts...)
		if err != nil {
			return nil, fmt.Errorf("attestation: evidence[%d] issuer=%q: %w",
				i, ev.Issuer, err)
		}
		out[i] = rep
	}
	return out, nil
}

// evidenceKindForIssuer maps a wire-stable issuer string to the
// cc/attest verifier Kind that handles it. Returns ("", false) when
// the issuer has no production verifier registered yet.
func evidenceKindForIssuer(issuer string) (attest.Kind, bool) {
	switch issuer {
	case "amd.sev.snp":
		return attest.KindSEVSNP, true
	case "intel.tdx":
		return attest.KindTDX, true
	case "nvidia.nras.v1":
		return attest.KindNVTrust, true
	default:
		return "", false
	}
}

// hasGPUEvidence reports whether at least one evidence entry is a GPU
// attestation report (NRAS or vendor equivalent). Used by validate() to
// reject envelopes that claim composite trust without any GPU evidence.
func hasGPUEvidence(evs []Evidence) bool {
	for i := range evs {
		switch evs[i].Kind {
		case EvidenceGPUNRASReport, EvidenceGPUVendorReport:
			return true
		}
	}
	return false
}

// envelopeBody is the subset of CompositeAttestation that participates in
// the digest. Today every field of CompositeAttestation participates;
// envelopeBody exists so future fields (signatures over the digest) can be
// added to CompositeAttestation without changing the digest formula.
type envelopeBody struct {
	Version           string                      `cbor:"version"`
	NodeID            string                      `cbor:"node_id"`
	WorkerIDs         []string                    `cbor:"worker_ids"`
	AssertedTrustMode lattice.ComputeTrustMode    `cbor:"asserted_trust_mode"`
	AssertedIOLevel   lattice.ConfidentialIOLevel `cbor:"asserted_io_level"`
	Evidence          []Evidence                  `cbor:"evidence"`
	IssuedAt          time.Time                   `cbor:"issued_at"`
}

// ErrNilEnvelope is returned when a nil receiver / nil argument reaches
// Root, Marshal, or Validate.
var ErrNilEnvelope = errors.New("attestation: nil envelope")
