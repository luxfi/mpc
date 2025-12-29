// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"errors"

	lattice "github.com/luxfi/lattice/v7/types"
)

// LanePolicy describes the trust + IO floor that a scheduling lane
// enforces. A lane is the runtime resource pool a workload is dispatched
// into (e.g. "public-inference", "private-inference", "validator-keys",
// "fhe-precompile"). The scheduler picks a lane based on workload privacy
// class, then picks a worker that meets the lane's floor.
//
// LanePolicy is the operator-controlled configuration: an operator who
// adopts a stricter policy (e.g. demands ConfidentialIO on every private
// lane) edits LanePolicy, not the workload. The split between LanePolicy
// (operator) and WorkloadPolicy (per-request) keeps the truth-table
// debuggable: every Eligible() check is a function of two policies and a
// capability.
type LanePolicy struct {
	// Name is a human-readable identifier; not part of the gating logic.
	Name string

	// MinTrustMode is the floor for ComputeTrustMode. A worker with
	// TrustMode < MinTrustMode is ineligible for this lane regardless of
	// any other field.
	MinTrustMode lattice.ComputeTrustMode

	// MinIOLevel is the floor for ConfidentialIOLevel. Same gating as
	// MinTrustMode.
	MinIOLevel lattice.ConfidentialIOLevel

	// AllowedArches is the set of GPU archs this lane permits. An empty
	// slice means "any valid arch". Membership check is exact-match
	// against GPUArch values; SupportsConfidentialCompute() is NOT
	// inferred.
	AllowedArches []GPUArch

	// AllowedBackends is the set of permitted runtime backends. Empty
	// means any.
	AllowedBackends []GPUBackend

	// RequireAttestation, when true, refuses any worker whose
	// AttestationRoot is the zero value, even if MinTrustMode is
	// PublicDeterministic. Used for lanes that need a logged identity
	// even on public workloads.
	RequireAttestation bool
}

// Validate performs cheap structural checks on the lane policy.
func (lp *LanePolicy) Validate() error {
	if lp == nil {
		return errors.New("registry: nil lane policy")
	}
	if lp.Name == "" {
		return errors.New("registry: lane policy name required")
	}
	if !lp.MinTrustMode.Valid() {
		return errors.New("registry: invalid lane min_trust_mode")
	}
	if !lp.MinIOLevel.Valid() {
		return errors.New("registry: invalid lane min_io_level")
	}
	for _, a := range lp.AllowedArches {
		if !a.Valid() {
			return errors.New("registry: invalid lane allowed_arch")
		}
	}
	for _, b := range lp.AllowedBackends {
		if !b.Valid() {
			return errors.New("registry: invalid lane allowed_backend")
		}
	}
	return nil
}

// WorkloadPolicy is the per-workload policy carried by a scheduling
// request. It expresses the workload's *minimum* requirements; the lane
// adds a floor on top. The effective floor for any worker is
// `max(LanePolicy.Min..., WorkloadPolicy.Min...)`.
type WorkloadPolicy struct {
	// PrivacyClass is the workload's data-handling tag.
	PrivacyClass lattice.WorkloadPrivacyClass

	// MinTrustMode is the workload's required floor. The effective floor
	// for the chosen worker is max(LanePolicy.MinTrustMode, this).
	MinTrustMode lattice.ComputeTrustMode

	// MinIOLevel is the workload's IO floor.
	MinIOLevel lattice.ConfidentialIOLevel

	// RequiredArches is the set of arches this workload accepts. Empty
	// means any (subject to the lane's AllowedArches).
	RequiredArches []GPUArch

	// RequiredBackends is the set of backends this workload accepts.
	// Empty means any.
	RequiredBackends []GPUBackend

	// MinVRAMBytes is the minimum device memory the workload requires.
	// 0 means no minimum.
	MinVRAMBytes uint64

	// RequiredInterconnect is the minimum peer-fabric strength. Comparison
	// is `>=` on the underlying value, mirroring trust mode semantics.
	RequiredInterconnect PeerInterconnect
}

// Validate performs cheap structural checks on the workload policy.
func (wp *WorkloadPolicy) Validate() error {
	if wp == nil {
		return errors.New("registry: nil workload policy")
	}
	if !wp.PrivacyClass.Valid() {
		return errors.New("registry: invalid workload privacy_class")
	}
	if !wp.MinTrustMode.Valid() {
		return errors.New("registry: invalid workload min_trust_mode")
	}
	if !wp.MinIOLevel.Valid() {
		return errors.New("registry: invalid workload min_io_level")
	}
	if !wp.RequiredInterconnect.Valid() {
		return errors.New("registry: invalid workload required_interconnect")
	}
	for _, a := range wp.RequiredArches {
		if !a.Valid() {
			return errors.New("registry: invalid workload required_arch")
		}
	}
	for _, b := range wp.RequiredBackends {
		if !b.Valid() {
			return errors.New("registry: invalid workload required_backend")
		}
	}
	// Privacy class implies a minimum trust mode floor: regulated /
	// validator workloads must run on TrustCpuGpuCompositeTEE or stronger.
	// We enforce this here so a misconfigured workload cannot downgrade
	// itself by accident.
	switch wp.PrivacyClass {
	case lattice.PrivacyValidatorKeyMaterial, lattice.PrivacyRegulatedOrderflow:
		if wp.MinTrustMode < lattice.TrustCpuGpuCompositeTEE {
			return errors.New("registry: validator/regulated workloads require TrustCpuGpuCompositeTEE+")
		}
	}
	return nil
}

// Eligible reports whether worker w may run a workload tagged with wp on
// lane lp. It is the canonical eligibility check; every scheduler decision
// in the GPU runtime goes through it.
//
// The check is a conjunction of independent gates -- all must pass:
//
//  1. lane: w.TrustMode >= lp.MinTrustMode
//  2. lane: w.IOLevel   >= lp.MinIOLevel
//  3. lane: w.Arch     in lp.AllowedArches (or AllowedArches empty)
//  4. lane: w.Backend  in lp.AllowedBackends (or AllowedBackends empty)
//  5. lane: lp.RequireAttestation -> w.AttestationRoot != zero
//  6. workload: w.TrustMode >= wp.MinTrustMode
//  7. workload: w.IOLevel   >= wp.MinIOLevel
//  8. workload: w.Arch    in wp.RequiredArches (or RequiredArches empty)
//  9. workload: w.Backend in wp.RequiredBackends (or RequiredBackends empty)
//  10. workload: w.VRAMBytes      >= wp.MinVRAMBytes
//  11. workload: w.Interconnect   >= wp.RequiredInterconnect
//  12. consistency: privacy classes that require TEE arch are honoured
//
// Failures return a non-nil error describing the *first* gate that failed.
// A nil error means w is eligible.
//
// Eligible does NOT call Validate on its inputs. Callers are expected to
// have validated lp, wp, and w before invoking the scheduler hot path.
func Eligible(lp *LanePolicy, wp *WorkloadPolicy, w *WorkerCapability) error {
	if lp == nil || wp == nil || w == nil {
		return errors.New("registry: eligible: nil input")
	}

	// Gate 1: lane min trust mode.
	if w.TrustMode < lp.MinTrustMode {
		return ErrIneligibleLaneTrust
	}
	// Gate 2: lane min IO level.
	if w.IOLevel < lp.MinIOLevel {
		return ErrIneligibleLaneIO
	}
	// Gate 3: lane allowed arches.
	if !archAllowed(lp.AllowedArches, w.Arch) {
		return ErrIneligibleLaneArch
	}
	// Gate 4: lane allowed backends.
	if !backendAllowed(lp.AllowedBackends, w.Backend) {
		return ErrIneligibleLaneBackend
	}
	// Gate 5: lane requires attestation.
	if lp.RequireAttestation && w.AttestationRoot == ([32]byte{}) {
		return ErrIneligibleNoAttestation
	}
	// Gate 6: workload min trust mode.
	if w.TrustMode < wp.MinTrustMode {
		return ErrIneligibleWorkloadTrust
	}
	// Gate 7: workload min IO level.
	if w.IOLevel < wp.MinIOLevel {
		return ErrIneligibleWorkloadIO
	}
	// Gate 8: workload required arches.
	if !archAllowed(wp.RequiredArches, w.Arch) {
		return ErrIneligibleWorkloadArch
	}
	// Gate 9: workload required backends.
	if !backendAllowed(wp.RequiredBackends, w.Backend) {
		return ErrIneligibleWorkloadBackend
	}
	// Gate 10: workload VRAM floor.
	if w.VRAMBytes < wp.MinVRAMBytes {
		return ErrIneligibleVRAM
	}
	// Gate 11: workload interconnect floor.
	if w.Interconnect < wp.RequiredInterconnect {
		return ErrIneligibleInterconnect
	}
	// Gate 12: privacy-class consistency. The TEE arch requirement is
	// already encoded in WorkerCapability.Validate; here we re-check it
	// against the workload class to defend against an unvalidated worker
	// record slipping past the API edge.
	switch wp.PrivacyClass {
	case lattice.PrivacyValidatorKeyMaterial,
		lattice.PrivacyRegulatedOrderflow,
		lattice.PrivacyPrivateModelWeights,
		lattice.PrivacyPrivateUserData:
		if !w.Arch.SupportsConfidentialCompute() {
			return ErrIneligiblePrivacyArch
		}
	}
	return nil
}

// archAllowed reports whether a is in the allowed set, where an empty
// allowed set means "any valid arch is permitted".
func archAllowed(allowed []GPUArch, a GPUArch) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, x := range allowed {
		if x == a {
			return true
		}
	}
	return false
}

// backendAllowed reports whether b is in the allowed set, where an empty
// allowed set means "any valid backend is permitted".
func backendAllowed(allowed []GPUBackend, b GPUBackend) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, x := range allowed {
		if x == b {
			return true
		}
	}
	return false
}

// Eligibility error sentinels. The scheduler logs these by identity; do
// not change the strings without updating downstream metric labels.
var (
	ErrIneligibleLaneTrust       = errors.New("registry: lane min_trust_mode not met")
	ErrIneligibleLaneIO          = errors.New("registry: lane min_io_level not met")
	ErrIneligibleLaneArch        = errors.New("registry: lane allowed_arches mismatch")
	ErrIneligibleLaneBackend     = errors.New("registry: lane allowed_backends mismatch")
	ErrIneligibleNoAttestation   = errors.New("registry: lane require_attestation but worker has none")
	ErrIneligibleWorkloadTrust   = errors.New("registry: workload min_trust_mode not met")
	ErrIneligibleWorkloadIO      = errors.New("registry: workload min_io_level not met")
	ErrIneligibleWorkloadArch    = errors.New("registry: workload required_arches mismatch")
	ErrIneligibleWorkloadBackend = errors.New("registry: workload required_backends mismatch")
	ErrIneligibleVRAM            = errors.New("registry: workload min_vram not met")
	ErrIneligibleInterconnect    = errors.New("registry: workload required_interconnect not met")
	ErrIneligiblePrivacyArch     = errors.New("registry: privacy class requires TEE-capable arch")
)
