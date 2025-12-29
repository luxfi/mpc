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
// GPUArch
// -----------------------------------------------------------------------------

func TestGPUArch_StableValues(t *testing.T) {
	cases := []struct {
		arch GPUArch
		want uint8
	}{
		{GPUArchUnknown, 0},
		{GPUArchAmpere, 1},
		{GPUArchHopper, 2},
		{GPUArchBlackwell, 3},
		{GPUArchAdaLovelace, 4},
		{GPUArchAppleSilicon, 5},
		{GPUArchAMDCDNA, 6},
		{GPUArchIntelXeHPC, 7},
	}
	for _, c := range cases {
		if uint8(c.arch) != c.want {
			t.Errorf("%s: got %d want %d", c.arch, uint8(c.arch), c.want)
		}
	}
}

func TestGPUArch_String(t *testing.T) {
	if got := GPUArchHopper.String(); got != "Hopper" {
		t.Errorf("got %q want Hopper", got)
	}
	if got := GPUArch(99).String(); got != "Unknown" {
		t.Errorf("got %q want Unknown", got)
	}
}

func TestGPUArch_Valid(t *testing.T) {
	for a := GPUArch(0); a <= GPUArchIntelXeHPC; a++ {
		if !a.Valid() {
			t.Errorf("expected %s to be valid", a)
		}
	}
	if GPUArch(99).Valid() {
		t.Error("expected 99 to be invalid")
	}
}

func TestGPUArch_SupportsConfidentialCompute(t *testing.T) {
	cases := []struct {
		arch GPUArch
		want bool
	}{
		{GPUArchUnknown, false},
		{GPUArchAmpere, false},
		{GPUArchHopper, true},
		{GPUArchBlackwell, true},
		{GPUArchAdaLovelace, false},
		{GPUArchAppleSilicon, false},
		{GPUArchAMDCDNA, false},
		{GPUArchIntelXeHPC, false},
	}
	for _, c := range cases {
		if got := c.arch.SupportsConfidentialCompute(); got != c.want {
			t.Errorf("%s: got %v want %v", c.arch, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// GPUBackend
// -----------------------------------------------------------------------------

func TestGPUBackend_StableValues(t *testing.T) {
	cases := []struct {
		b    GPUBackend
		want uint8
	}{
		{GPUBackendUnknown, 0},
		{GPUBackendCUDA, 1},
		{GPUBackendROCm, 2},
		{GPUBackendMetal, 3},
		{GPUBackendOneAPI, 4},
		{GPUBackendVulkan, 5},
		{GPUBackendWebGPU, 6},
		{GPUBackendCPU, 7},
	}
	for _, c := range cases {
		if uint8(c.b) != c.want {
			t.Errorf("%s: got %d want %d", c.b, uint8(c.b), c.want)
		}
	}
}

func TestGPUBackend_Valid(t *testing.T) {
	for b := GPUBackend(0); b <= GPUBackendCPU; b++ {
		if !b.Valid() {
			t.Errorf("expected %s to be valid", b)
		}
	}
	if GPUBackend(99).Valid() {
		t.Error("expected 99 to be invalid")
	}
}

// -----------------------------------------------------------------------------
// PeerInterconnect
// -----------------------------------------------------------------------------

func TestPeerInterconnect_Order(t *testing.T) {
	chain := []PeerInterconnect{
		PeerInterconnectNone,
		PeerInterconnectPCIe,
		PeerInterconnectNVLink,
		PeerInterconnectNVSwitch,
		PeerInterconnectInfinity,
	}
	for i := 1; i < len(chain); i++ {
		if !(chain[i] > chain[i-1]) {
			t.Fatalf("interconnect ordering broken at %s -> %s", chain[i-1], chain[i])
		}
	}
}

// -----------------------------------------------------------------------------
// WorkerCapability.Validate
// -----------------------------------------------------------------------------

func goodWorker() WorkerCapability {
	return WorkerCapability{
		WorkerID:        "node-a/0",
		NodeID:          "node-a",
		Arch:            GPUArchHopper,
		Backend:         GPUBackendCUDA,
		VRAMBytes:       80 << 30,
		FP16TFlops:      1000,
		FP8TFlops:       2000,
		INT8TOps:        4000,
		Interconnect:    PeerInterconnectNVSwitch,
		TrustMode:       lattice.TrustCpuGpuCompositeTEE,
		IOLevel:         lattice.IOLevelCpuGpuComposite,
		AttestationRoot: [32]byte{0x01},
	}
}

func TestWorkerCapability_Validate_Good(t *testing.T) {
	w := goodWorker()
	if err := w.Validate(); err != nil {
		t.Fatalf("good worker rejected: %v", err)
	}
}

func TestWorkerCapability_Validate_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*WorkerCapability)
		errSub string
	}{
		{"nil_worker_id", func(w *WorkerCapability) { w.WorkerID = "" }, "worker_id required"},
		{"nil_node_id", func(w *WorkerCapability) { w.NodeID = "" }, "node_id required"},
		{"prefix_mismatch", func(w *WorkerCapability) { w.WorkerID = "other/0" }, "prefixed with node_id"},
		{"bad_arch", func(w *WorkerCapability) { w.Arch = GPUArch(99) }, "invalid arch"},
		{"bad_backend", func(w *WorkerCapability) { w.Backend = GPUBackend(99) }, "invalid backend"},
		{"bad_interconnect", func(w *WorkerCapability) { w.Interconnect = PeerInterconnect(99) }, "invalid interconnect"},
		{"bad_trust", func(w *WorkerCapability) { w.TrustMode = lattice.ComputeTrustMode(99) }, "invalid trust_mode"},
		{"bad_io", func(w *WorkerCapability) { w.IOLevel = lattice.ConfidentialIOLevel(99) }, "invalid io_level"},
		{
			"composite_on_ampere",
			func(w *WorkerCapability) {
				w.Arch = GPUArchAmpere
				w.TrustMode = lattice.TrustCpuGpuCompositeTEE
			},
			"requires Hopper or Blackwell",
		},
		{
			"composite_no_root",
			func(w *WorkerCapability) {
				w.AttestationRoot = [32]byte{}
			},
			"requires attestation_root",
		},
		{
			"protected_io_without_confidential_trust",
			func(w *WorkerCapability) {
				w.IOLevel = lattice.IOLevelProtectedCpuGpuTransfer
				w.TrustMode = lattice.TrustCpuGpuCompositeTEE
			},
			"protected IO level requires TrustConfidentialIO",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := goodWorker()
			c.mut(&w)
			err := w.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.errSub)
			}
			if !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("expected error containing %q, got %q", c.errSub, err.Error())
			}
		})
	}
}

func TestWorkerCapability_Validate_NilReceiver(t *testing.T) {
	var w *WorkerCapability
	if err := w.Validate(); !errors.Is(err, ErrNilCapability) {
		t.Fatalf("expected ErrNilCapability, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// NodeCapability.Validate
// -----------------------------------------------------------------------------

func goodNode() NodeCapability {
	w := goodWorker()
	return NodeCapability{
		NodeID:     "node-a",
		Region:     "us-east-1a",
		OperatorID: "lux",
		CPUTeeType: "amd-sev-snp",
		Workers:    []WorkerCapability{w},
	}
}

func TestNodeCapability_Validate_Good(t *testing.T) {
	n := goodNode()
	if err := n.Validate(); err != nil {
		t.Fatalf("good node rejected: %v", err)
	}
}

func TestNodeCapability_Validate_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*NodeCapability)
		errSub string
	}{
		{"nil_node_id", func(n *NodeCapability) { n.NodeID = "" }, "node_id required"},
		{"nil_region", func(n *NodeCapability) { n.Region = "" }, "region required"},
		{"nil_operator", func(n *NodeCapability) { n.OperatorID = "" }, "operator_id required"},
		{"no_workers", func(n *NodeCapability) { n.Workers = nil }, "at least one worker"},
		{
			"worker_node_mismatch",
			func(n *NodeCapability) {
				n.Workers[0].NodeID = "other"
				n.Workers[0].WorkerID = "other/0"
			},
			"must match",
		},
		{
			"duplicate_worker_id",
			func(n *NodeCapability) {
				n.Workers = append(n.Workers, n.Workers[0])
			},
			"duplicate worker_id",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := goodNode()
			c.mut(&n)
			err := n.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.errSub)
			}
			if !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("expected error containing %q, got %q", c.errSub, err.Error())
			}
		})
	}
}

func TestNodeCapability_Validate_NilReceiver(t *testing.T) {
	var n *NodeCapability
	if err := n.Validate(); !errors.Is(err, ErrNilCapability) {
		t.Fatalf("expected ErrNilCapability, got %v", err)
	}
}
