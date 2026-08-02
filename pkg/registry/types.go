// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Package registry defines the worker / node capability records that the
// Lux GPU Runtime scheduler uses to pick a target for a workload.
//
// The registry is the single source of truth for "what can this node do".
// A capability record is published by each worker (after it has produced a
// composite attestation; see pkg/attestation) and consumed by the scheduler
// to gate workloads through LanePolicy.Eligible / WorkloadPolicy.Eligible.
//
// The trust + privacy enums (ComputeTrustMode, ConfidentialIOLevel,
// WorkloadPrivacyClass) live in github.com/luxfi/lattice/v7/types because
// they are also imported by FHE / KMS / cevm. This package only adds the
// hardware-shape fields (GPU arch, backend, VRAM, peer interconnect, etc.)
// that the scheduler needs on top.
//
// Reference: LP-137-TRUST-REGISTRY.md.
package registry

import (
	"errors"
	"strings"

	lattice "github.com/luxfi/lattice/v7/types"
)

// GPUArch identifies the architectural family of a GPU. The scheduler uses
// it to decide whether a workload that requires a specific feature (e.g.
// confidential compute on Hopper, transformer engine v2 on Blackwell) can
// be placed on this worker.
//
// Underlying values are stable and part of the wire / log contract. The
// String() method is the canonical text form. New variants append at the
// end of the order; reordering is a breaking change.
type GPUArch uint8

const (
	GPUArchUnknown      GPUArch = 0
	GPUArchAmpere       GPUArch = 1 // A100, A40, A30, A10
	GPUArchHopper       GPUArch = 2 // H100, H200 -- first NVIDIA CC TEE
	GPUArchBlackwell    GPUArch = 3 // B100, B200, GB200 -- second-gen CC + TEE-IO
	GPUArchAdaLovelace  GPUArch = 4 // L40, L40S, RTX Ada
	GPUArchAppleSilicon GPUArch = 5 // Apple M-series (Metal/MPS)
	GPUArchAMDCDNA      GPUArch = 6 // MI250X, MI300X (ROCm)
	GPUArchIntelXeHPC   GPUArch = 7 // Ponte Vecchio (oneAPI)
)

// String returns a stable, human-readable name for the GPU arch.
func (a GPUArch) String() string {
	switch a {
	case GPUArchUnknown:
		return "Unknown"
	case GPUArchAmpere:
		return "Ampere"
	case GPUArchHopper:
		return "Hopper"
	case GPUArchBlackwell:
		return "Blackwell"
	case GPUArchAdaLovelace:
		return "AdaLovelace"
	case GPUArchAppleSilicon:
		return "AppleSilicon"
	case GPUArchAMDCDNA:
		return "AMDCDNA"
	case GPUArchIntelXeHPC:
		return "IntelXeHPC"
	default:
		return "Unknown"
	}
}

// Valid reports whether a is one of the defined arch values.
func (a GPUArch) Valid() bool {
	return a <= GPUArchIntelXeHPC
}

// SupportsConfidentialCompute reports whether the arch has on-die hardware
// support for confidential compute (TEE / TEE-IO). Used by the scheduler
// to short-circuit eligibility for ComputeTrustMode >= CpuGpuCompositeTEE.
//
// Hopper (H100) introduced GPU CC. Blackwell (B100/B200) extends with
// TEE-IO. No other published arch has on-die CC at registry-publication
// time; this function returns false for everything else.
func (a GPUArch) SupportsConfidentialCompute() bool {
	return a == GPUArchHopper || a == GPUArchBlackwell
}

// GPUBackend identifies the kernel-execution stack the worker has loaded.
// One worker may report multiple backends (e.g. CUDA + Triton on the same
// device); each capability record carries one primary backend, and the
// scheduler matches it against the workload's required-backend set.
type GPUBackend uint8

const (
	GPUBackendUnknown GPUBackend = 0
	GPUBackendCUDA    GPUBackend = 1 // NVIDIA CUDA C++/PTX
	GPUBackendROCm    GPUBackend = 2 // AMD HIP
	GPUBackendMetal   GPUBackend = 3 // Apple Metal / MPS
	GPUBackendOneAPI  GPUBackend = 4 // Intel oneAPI / SYCL
	GPUBackendVulkan  GPUBackend = 5 // Cross-vendor Vulkan compute
	GPUBackendWebGPU  GPUBackend = 6 // WebGPU / wgpu (browser + native)
	GPUBackendCPU     GPUBackend = 7 // CPU fallback (no GPU)
)

// String returns a stable, human-readable name for the backend.
func (b GPUBackend) String() string {
	switch b {
	case GPUBackendUnknown:
		return "Unknown"
	case GPUBackendCUDA:
		return "CUDA"
	case GPUBackendROCm:
		return "ROCm"
	case GPUBackendMetal:
		return "Metal"
	case GPUBackendOneAPI:
		return "OneAPI"
	case GPUBackendVulkan:
		return "Vulkan"
	case GPUBackendWebGPU:
		return "WebGPU"
	case GPUBackendCPU:
		return "CPU"
	default:
		return "Unknown"
	}
}

// Valid reports whether b is one of the defined backend values.
func (b GPUBackend) Valid() bool {
	return b <= GPUBackendCPU
}

// PeerInterconnect identifies the highest-bandwidth peer-to-peer fabric
// available on the worker. A scheduler that places a multi-GPU workload
// requiring NVLink or NVSwitch will refuse a worker that reports only PCIe.
type PeerInterconnect uint8

const (
	PeerInterconnectNone     PeerInterconnect = 0 // single-GPU, no peer fabric
	PeerInterconnectPCIe     PeerInterconnect = 1 // PCIe Gen4/Gen5 only
	PeerInterconnectNVLink   PeerInterconnect = 2 // NVLink point-to-point
	PeerInterconnectNVSwitch PeerInterconnect = 3 // NVSwitch all-to-all
	PeerInterconnectInfinity PeerInterconnect = 4 // AMD Infinity Fabric
)

// String returns a stable name for the interconnect.
func (p PeerInterconnect) String() string {
	switch p {
	case PeerInterconnectNone:
		return "None"
	case PeerInterconnectPCIe:
		return "PCIe"
	case PeerInterconnectNVLink:
		return "NVLink"
	case PeerInterconnectNVSwitch:
		return "NVSwitch"
	case PeerInterconnectInfinity:
		return "InfinityFabric"
	default:
		return "Unknown"
	}
}

// Valid reports whether p is one of the defined interconnect values.
func (p PeerInterconnect) Valid() bool {
	return p <= PeerInterconnectInfinity
}

// WorkerCapability is the per-worker capability record. It describes one
// addressable execution endpoint -- a single GPU, an Apple Metal device,
// or a CPU-only fallback -- on a node.
//
// The struct is the canonical wire form: every field is required, none are
// optional. Validate() performs cheap structural checks at the API edge;
// it does NOT verify the attestation -- that is done by callers using
// pkg/attestation.
type WorkerCapability struct {
	// WorkerID is a globally unique identifier for this execution endpoint.
	// Convention: "<NodeID>/<DeviceIndex>" (e.g. "n3-h100-01/0").
	WorkerID string

	// NodeID is the node that hosts this worker (matches NodeCapability.NodeID).
	NodeID string

	// Arch + Backend describe the hardware + runtime stack. Both must be
	// Valid().
	Arch    GPUArch
	Backend GPUBackend

	// VRAMBytes is the total device memory in bytes. 0 for CPU workers.
	VRAMBytes uint64

	// FP16TFlops + FP8TFlops + INT8TOps are the worker's published peak
	// compute throughput. Used by the scheduler to size workloads.
	FP16TFlops uint32 // FP16 dense TFLOPs (Tensor Cores)
	FP8TFlops  uint32 // FP8 dense TFLOPs; 0 if unsupported (pre-Hopper)
	INT8TOps   uint32 // INT8 dense TOPs

	// Interconnect is the highest-bandwidth peer fabric available between
	// this worker and any sibling worker on the same node.
	Interconnect PeerInterconnect

	// TrustMode + IOLevel are the strongest guarantees this worker can
	// currently honour. Set after attestation. A worker that has not yet
	// attested reports TrustPublicDeterministic + IOLevelNone.
	TrustMode lattice.ComputeTrustMode
	IOLevel   lattice.ConfidentialIOLevel

	// AttestationRoot is the SHA-256 of the worker's most recent composite
	// attestation envelope (see pkg/attestation.CompositeAttestation.Root).
	// Zero ([32]byte{}) iff the worker has not produced an attestation;
	// such workers are forced to TrustPublicDeterministic regardless of
	// the TrustMode field above.
	AttestationRoot [32]byte
}

// Validate performs structural checks against the worker capability. It
// rejects records that the scheduler cannot reason about. It does NOT
// verify the attestation -- callers must do that separately.
func (w *WorkerCapability) Validate() error {
	if w == nil {
		return ErrNilCapability
	}
	if w.WorkerID == "" {
		return errors.New("registry: worker_id required")
	}
	if w.NodeID == "" {
		return errors.New("registry: node_id required")
	}
	if !strings.HasPrefix(w.WorkerID, w.NodeID+"/") {
		return errors.New("registry: worker_id must be prefixed with node_id/")
	}
	if !w.Arch.Valid() {
		return errors.New("registry: invalid arch")
	}
	if !w.Backend.Valid() {
		return errors.New("registry: invalid backend")
	}
	if !w.Interconnect.Valid() {
		return errors.New("registry: invalid interconnect")
	}
	if !w.TrustMode.Valid() {
		return errors.New("registry: invalid trust_mode")
	}
	if !w.IOLevel.Valid() {
		return errors.New("registry: invalid io_level")
	}
	// Trust mode >= CpuGpuCompositeTEE requires arch with on-die CC support.
	if w.TrustMode >= lattice.TrustCpuGpuCompositeTEE && !w.Arch.SupportsConfidentialCompute() {
		return errors.New("registry: trust_mode >= CpuGpuCompositeTEE requires Hopper or Blackwell arch")
	}
	// Composite trust requires a non-zero attestation root.
	if w.TrustMode >= lattice.TrustCpuGpuCompositeTEE && w.AttestationRoot == ([32]byte{}) {
		return errors.New("registry: trust_mode >= CpuGpuCompositeTEE requires attestation_root")
	}
	// IO level cannot exceed what the trust mode supports. A worker that
	// claims FullDeviceIOAttested without ConfidentialIO trust mode is
	// inconsistent.
	if w.IOLevel >= lattice.IOLevelProtectedCpuGpuTransfer && w.TrustMode < lattice.TrustConfidentialIO {
		return errors.New("registry: protected IO level requires TrustConfidentialIO")
	}
	return nil
}

// NodeCapability is the per-node capability record. A node hosts one or
// more WorkerCapability entries plus node-level metadata (CPU TEE type,
// region, operator identity).
type NodeCapability struct {
	// NodeID is a globally unique node identifier.
	NodeID string

	// Region is the physical region (e.g. "us-east-1a", "lux-sfo3-az1").
	// Used for placement constraints + co-residency rules.
	Region string

	// OperatorID identifies the operator account that runs this node
	// (e.g. an IAM org slug). Used for tenant isolation policies.
	OperatorID string

	// CPUTeeType is a free-form tag for the host CPU TEE. Empty string
	// means no CPU TEE. Canonical values: "amd-sev-snp", "intel-tdx",
	// "intel-sgx" (legacy), "arm-cca".
	CPUTeeType string

	// Workers are the execution endpoints hosted on this node. At least
	// one entry; every entry's NodeID must match this NodeID.
	Workers []WorkerCapability

	// AttestationRoot is the SHA-256 of the node's most-recent composite
	// attestation envelope. Distinct from per-worker roots: covers host /
	// kernel / firmware components, not GPU-specific evidence.
	AttestationRoot [32]byte
}

// Validate performs structural checks against the node capability. Each
// WorkerCapability is also validated; the first failure short-circuits.
func (n *NodeCapability) Validate() error {
	if n == nil {
		return ErrNilCapability
	}
	if n.NodeID == "" {
		return errors.New("registry: node_id required")
	}
	if n.Region == "" {
		return errors.New("registry: region required")
	}
	if n.OperatorID == "" {
		return errors.New("registry: operator_id required")
	}
	if len(n.Workers) == 0 {
		return errors.New("registry: at least one worker required")
	}
	seen := make(map[string]struct{}, len(n.Workers))
	for i := range n.Workers {
		w := &n.Workers[i]
		if w.NodeID != n.NodeID {
			return errors.New("registry: worker.node_id must match node.node_id")
		}
		if _, dup := seen[w.WorkerID]; dup {
			return errors.New("registry: duplicate worker_id")
		}
		seen[w.WorkerID] = struct{}{}
		if err := w.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ErrNilCapability is returned by Validate() when called on a nil receiver.
var ErrNilCapability = errors.New("registry: nil capability")
