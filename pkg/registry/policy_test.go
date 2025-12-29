// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package registry

import (
	"errors"
	"strings"
	"testing"

	lattice "github.com/luxfi/lattice/v7/types"
)

// -----------------------------------------------------------------------------
// LanePolicy + WorkloadPolicy validation
// -----------------------------------------------------------------------------

func TestLanePolicy_Validate(t *testing.T) {
	good := LanePolicy{
		Name:         "private-inference",
		MinTrustMode: lattice.TrustCpuGpuCompositeTEE,
		MinIOLevel:   lattice.IOLevelCpuGpuComposite,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good lane policy rejected: %v", err)
	}

	cases := []struct {
		name   string
		mut    func(*LanePolicy)
		errSub string
	}{
		{"nil_name", func(lp *LanePolicy) { lp.Name = "" }, "name required"},
		{"bad_trust", func(lp *LanePolicy) { lp.MinTrustMode = lattice.ComputeTrustMode(99) }, "invalid lane min_trust_mode"},
		{"bad_io", func(lp *LanePolicy) { lp.MinIOLevel = lattice.ConfidentialIOLevel(99) }, "invalid lane min_io_level"},
		{"bad_arch", func(lp *LanePolicy) { lp.AllowedArches = []GPUArch{GPUArch(99)} }, "invalid lane allowed_arch"},
		{"bad_backend", func(lp *LanePolicy) { lp.AllowedBackends = []GPUBackend{GPUBackend(99)} }, "invalid lane allowed_backend"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lp := good
			c.mut(&lp)
			err := lp.Validate()
			if err == nil || !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("expected error containing %q, got %v", c.errSub, err)
			}
		})
	}
}

func TestWorkloadPolicy_Validate(t *testing.T) {
	good := WorkloadPolicy{
		PrivacyClass:         lattice.PrivacyPrivateUserData,
		MinTrustMode:         lattice.TrustCpuGpuCompositeTEE,
		MinIOLevel:           lattice.IOLevelCpuGpuComposite,
		RequiredInterconnect: PeerInterconnectPCIe,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good workload policy rejected: %v", err)
	}

	cases := []struct {
		name   string
		mut    func(*WorkloadPolicy)
		errSub string
	}{
		{"bad_privacy", func(wp *WorkloadPolicy) { wp.PrivacyClass = lattice.WorkloadPrivacyClass(99) }, "invalid workload privacy_class"},
		{"bad_trust", func(wp *WorkloadPolicy) { wp.MinTrustMode = lattice.ComputeTrustMode(99) }, "invalid workload min_trust_mode"},
		{"bad_io", func(wp *WorkloadPolicy) { wp.MinIOLevel = lattice.ConfidentialIOLevel(99) }, "invalid workload min_io_level"},
		{"bad_interconnect", func(wp *WorkloadPolicy) { wp.RequiredInterconnect = PeerInterconnect(99) }, "invalid workload required_interconnect"},
		{"bad_arch", func(wp *WorkloadPolicy) { wp.RequiredArches = []GPUArch{GPUArch(99)} }, "invalid workload required_arch"},
		{"bad_backend", func(wp *WorkloadPolicy) { wp.RequiredBackends = []GPUBackend{GPUBackend(99)} }, "invalid workload required_backend"},
		{
			"validator_must_be_composite",
			func(wp *WorkloadPolicy) {
				wp.PrivacyClass = lattice.PrivacyValidatorKeyMaterial
				wp.MinTrustMode = lattice.TrustAttestedGpuOnly
			},
			"validator/regulated workloads require",
		},
		{
			"regulated_must_be_composite",
			func(wp *WorkloadPolicy) {
				wp.PrivacyClass = lattice.PrivacyRegulatedOrderflow
				wp.MinTrustMode = lattice.TrustPublicDeterministic
			},
			"validator/regulated workloads require",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wp := good
			c.mut(&wp)
			err := wp.Validate()
			if err == nil || !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("expected error containing %q, got %v", c.errSub, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Eligible() truth table
// -----------------------------------------------------------------------------

// The truth table fixes a baseline {lane, workload, worker} where w is
// eligible, then mutates a single field to flip a single gate. Each row
// asserts the precise sentinel error returned. Adding a new gate to
// Eligible() requires adding a new row here.
//
// The baseline:
//   - Lane: composite TEE + composite IO, Hopper or Blackwell only,
//     CUDA only, attestation required.
//   - Workload: private-user-data, composite TEE + composite IO,
//     PCIe interconnect floor, 40 GB VRAM floor, no arch/backend filter.
//   - Worker: Hopper, CUDA, NVSwitch, ConfidentialIO, FullDeviceIOAttested,
//     80 GB VRAM, attested.

func baselineLane() LanePolicy {
	return LanePolicy{
		Name:               "private-inference",
		MinTrustMode:       lattice.TrustCpuGpuCompositeTEE,
		MinIOLevel:         lattice.IOLevelCpuGpuComposite,
		AllowedArches:      []GPUArch{GPUArchHopper, GPUArchBlackwell},
		AllowedBackends:    []GPUBackend{GPUBackendCUDA},
		RequireAttestation: true,
	}
}

func baselineWorkload() WorkloadPolicy {
	return WorkloadPolicy{
		PrivacyClass:         lattice.PrivacyPrivateUserData,
		MinTrustMode:         lattice.TrustCpuGpuCompositeTEE,
		MinIOLevel:           lattice.IOLevelCpuGpuComposite,
		RequiredInterconnect: PeerInterconnectPCIe,
		MinVRAMBytes:         40 << 30,
	}
}

func baselineWorker() WorkerCapability {
	return WorkerCapability{
		WorkerID:        "node-a/0",
		NodeID:          "node-a",
		Arch:            GPUArchHopper,
		Backend:         GPUBackendCUDA,
		VRAMBytes:       80 << 30,
		Interconnect:    PeerInterconnectNVSwitch,
		TrustMode:       lattice.TrustConfidentialIO,
		IOLevel:         lattice.IOLevelFullDeviceIOAttested,
		AttestationRoot: [32]byte{0x42},
	}
}

func TestEligible_Baseline(t *testing.T) {
	lp := baselineLane()
	wp := baselineWorkload()
	w := baselineWorker()
	if err := Eligible(&lp, &wp, &w); err != nil {
		t.Fatalf("baseline eligibility failed: %v", err)
	}
}

func TestEligible_NilInputs(t *testing.T) {
	lp := baselineLane()
	wp := baselineWorkload()
	w := baselineWorker()
	if err := Eligible(nil, &wp, &w); err == nil {
		t.Error("expected error for nil lane")
	}
	if err := Eligible(&lp, nil, &w); err == nil {
		t.Error("expected error for nil workload")
	}
	if err := Eligible(&lp, &wp, nil); err == nil {
		t.Error("expected error for nil worker")
	}
}

func TestEligible_TruthTable(t *testing.T) {
	type mut struct {
		mutLane     func(*LanePolicy)
		mutWorkload func(*WorkloadPolicy)
		mutWorker   func(*WorkerCapability)
	}
	cases := []struct {
		name string
		m    mut
		want error
	}{
		{
			name: "lane_trust_below_floor",
			m: mut{mutWorker: func(w *WorkerCapability) {
				w.TrustMode = lattice.TrustAttestedGpuOnly
			}},
			want: ErrIneligibleLaneTrust,
		},
		{
			name: "lane_io_below_floor",
			m: mut{mutWorker: func(w *WorkerCapability) {
				// Drop io to None but keep trust mode satisfying the lane
				// trust floor; protected IO consistency check at validate
				// time would catch this, but Eligible bypasses Validate
				// (callers validate beforehand). We test the ordering of
				// gates here.
				w.IOLevel = lattice.IOLevelCpuTeeOnly
			}},
			want: ErrIneligibleLaneIO,
		},
		{
			name: "lane_arch_not_allowed",
			m: mut{
				mutWorker: func(w *WorkerCapability) {
					w.Arch = GPUArchBlackwell
				},
				mutLane: func(lp *LanePolicy) {
					lp.AllowedArches = []GPUArch{GPUArchHopper}
				},
			},
			want: ErrIneligibleLaneArch,
		},
		{
			name: "lane_backend_not_allowed",
			m: mut{mutWorker: func(w *WorkerCapability) {
				w.Backend = GPUBackendROCm
			}},
			want: ErrIneligibleLaneBackend,
		},
		{
			name: "lane_requires_attestation_but_none",
			m: mut{mutWorker: func(w *WorkerCapability) {
				w.AttestationRoot = [32]byte{}
			}},
			want: ErrIneligibleNoAttestation,
		},
		{
			name: "workload_trust_below_floor",
			m: mut{
				mutLane: func(lp *LanePolicy) {
					// Drop lane floor so workload floor is the gate.
					lp.MinTrustMode = lattice.TrustPublicDeterministic
				},
				mutWorkload: func(wp *WorkloadPolicy) {
					wp.MinTrustMode = lattice.TrustZKOrFraudProofed
				},
			},
			want: ErrIneligibleWorkloadTrust,
		},
		{
			name: "workload_io_below_floor",
			m: mut{
				mutLane: func(lp *LanePolicy) {
					lp.MinIOLevel = lattice.IOLevelNone
				},
				mutWorkload: func(wp *WorkloadPolicy) {
					// Worker baseline has FullDeviceIOAttested -- bump
					// workload to require something stricter than that.
					wp.MinIOLevel = lattice.ConfidentialIOLevel(99)
				},
			},
			want: ErrIneligibleWorkloadIO,
		},
		{
			name: "workload_arch_not_required",
			m: mut{mutWorkload: func(wp *WorkloadPolicy) {
				wp.RequiredArches = []GPUArch{GPUArchBlackwell}
			}},
			want: ErrIneligibleWorkloadArch,
		},
		{
			name: "workload_backend_not_required",
			m: mut{mutWorkload: func(wp *WorkloadPolicy) {
				wp.RequiredBackends = []GPUBackend{GPUBackendROCm}
			}},
			want: ErrIneligibleWorkloadBackend,
		},
		{
			name: "workload_vram_floor",
			m: mut{mutWorkload: func(wp *WorkloadPolicy) {
				wp.MinVRAMBytes = 200 << 30 // 200 GB > 80 GB worker
			}},
			want: ErrIneligibleVRAM,
		},
		{
			name: "workload_interconnect_floor",
			m: mut{
				mutWorker: func(w *WorkerCapability) {
					w.Interconnect = PeerInterconnectPCIe
				},
				mutWorkload: func(wp *WorkloadPolicy) {
					wp.RequiredInterconnect = PeerInterconnectNVSwitch
				},
			},
			want: ErrIneligibleInterconnect,
		},
		{
			name: "privacy_class_requires_tee_arch_validator",
			m: mut{
				// Run the validator workload through a permissive lane and
				// drop the worker to Ampere (no TEE) to trigger gate 12.
				mutLane: func(lp *LanePolicy) {
					lp.MinTrustMode = lattice.TrustPublicDeterministic
					lp.MinIOLevel = lattice.IOLevelNone
					lp.AllowedArches = nil
					lp.AllowedBackends = nil
					lp.RequireAttestation = false
				},
				mutWorkload: func(wp *WorkloadPolicy) {
					wp.PrivacyClass = lattice.PrivacyValidatorKeyMaterial
					// Workload trust mode floor is permissive enough that
					// worker meets it; the privacy-class gate is what fails.
					wp.MinTrustMode = lattice.TrustPublicDeterministic
					wp.MinIOLevel = lattice.IOLevelNone
				},
				mutWorker: func(w *WorkerCapability) {
					w.Arch = GPUArchAmpere
					w.TrustMode = lattice.TrustAttestedGpuOnly
					w.IOLevel = lattice.IOLevelNone
				},
			},
			want: ErrIneligiblePrivacyArch,
		},
		{
			name: "privacy_class_requires_tee_arch_regulated",
			m: mut{
				mutLane: func(lp *LanePolicy) {
					lp.MinTrustMode = lattice.TrustPublicDeterministic
					lp.MinIOLevel = lattice.IOLevelNone
					lp.AllowedArches = nil
					lp.AllowedBackends = nil
					lp.RequireAttestation = false
				},
				mutWorkload: func(wp *WorkloadPolicy) {
					wp.PrivacyClass = lattice.PrivacyRegulatedOrderflow
					wp.MinTrustMode = lattice.TrustPublicDeterministic
					wp.MinIOLevel = lattice.IOLevelNone
				},
				mutWorker: func(w *WorkerCapability) {
					w.Arch = GPUArchAdaLovelace
					w.TrustMode = lattice.TrustAttestedGpuOnly
					w.IOLevel = lattice.IOLevelNone
				},
			},
			want: ErrIneligiblePrivacyArch,
		},
		{
			name: "public_workload_on_ampere_passes",
			m: mut{
				mutLane: func(lp *LanePolicy) {
					lp.MinTrustMode = lattice.TrustPublicDeterministic
					lp.MinIOLevel = lattice.IOLevelNone
					lp.AllowedArches = nil
					lp.AllowedBackends = nil
					lp.RequireAttestation = false
				},
				mutWorkload: func(wp *WorkloadPolicy) {
					wp.PrivacyClass = lattice.PrivacyPublic
					wp.MinTrustMode = lattice.TrustPublicDeterministic
					wp.MinIOLevel = lattice.IOLevelNone
				},
				mutWorker: func(w *WorkerCapability) {
					w.Arch = GPUArchAmpere
					w.TrustMode = lattice.TrustAttestedGpuOnly
					w.IOLevel = lattice.IOLevelNone
				},
			},
			want: nil, // public class on Ampere is fine
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lp := baselineLane()
			wp := baselineWorkload()
			w := baselineWorker()
			if c.m.mutLane != nil {
				c.m.mutLane(&lp)
			}
			if c.m.mutWorkload != nil {
				c.m.mutWorkload(&wp)
			}
			if c.m.mutWorker != nil {
				c.m.mutWorker(&w)
			}
			err := Eligible(&lp, &wp, &w)
			if !errors.Is(err, c.want) {
				t.Fatalf("Eligible(%s): got %v want %v", c.name, err, c.want)
			}
		})
	}
}

// TestEligible_GateOrdering pins the order in which gates are evaluated.
// A misclassified failure (e.g. reporting "VRAM" when the real problem is
// "lane trust") would mislead operators reading the metric labels. The
// order is documented in policy.go:Eligible(); this test is a regression
// guard against re-ordering.
func TestEligible_GateOrdering(t *testing.T) {
	lp := baselineLane()
	wp := baselineWorkload()
	w := baselineWorker()
	// Break multiple gates simultaneously and assert the *first* one wins.
	w.TrustMode = lattice.TrustAttestedGpuOnly // breaks gate 1 (lane trust)
	w.IOLevel = lattice.IOLevelCpuTeeOnly      // also breaks gate 2 (lane io)
	w.Backend = GPUBackendROCm                 // also breaks gate 4 (lane backend)
	w.VRAMBytes = 1 << 20                      // also breaks gate 10 (workload vram)

	err := Eligible(&lp, &wp, &w)
	if !errors.Is(err, ErrIneligibleLaneTrust) {
		t.Fatalf("expected gate 1 (lane trust) to win, got %v", err)
	}
}
