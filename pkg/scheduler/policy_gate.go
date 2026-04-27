// Package scheduler enforces workload-policy gates BEFORE a worker is
// allowed to participate in a sign / inference session.
//
// The scheduler is the only place that decides "this worker may produce
// a partial signature share for this workload". Every entry point into
// the MPC sign path consults this gate. Failure FAILS CLOSED — no
// fallback to "trust the coordinator".
//
// The types here are the scheduler's own view of v0.60 registry types.
// When pkg/registry lands the WorkloadPolicy / Worker structs they
// will be adapted via the WorkloadPolicySource interface — no code in
// this package changes.
package scheduler

import (
	"errors"
	"fmt"
)

// TrustMode classifies a worker's confidential-compute posture, ordered
// least-to-most trusted. The gate compares with >=, so callers can
// require a minimum tier.
type TrustMode uint8

const (
	// TrustNone — no confidential compute. Bare-metal or VM with no
	// memory encryption. Acceptable only for public workloads.
	TrustNone TrustMode = iota
	// TrustCVM — CPU TEE only (SEV-SNP, TDX). Memory encrypted, CPU
	// attested. GPU runs in plaintext.
	TrustCVM
	// TrustGPU — CPU TEE + GPU confidential compute (Hopper CC, Blackwell
	// CC). End-to-end PCIe encryption between CPU TEE and GPU.
	TrustGPU
	// TrustGPUMultiNode — TrustGPU + NVSwitch attested for multi-GPU
	// workloads. Required for tensor-parallel inference of large models.
	TrustGPUMultiNode
)

// String returns the canonical name for the trust tier.
func (t TrustMode) String() string {
	switch t {
	case TrustNone:
		return "none"
	case TrustCVM:
		return "cvm"
	case TrustGPU:
		return "gpu"
	case TrustGPUMultiNode:
		return "gpu_multinode"
	}
	return "invalid"
}

// IOLevel classifies the network/storage isolation of a worker. Used
// to enforce private-lane requirements (no egress to public internet,
// keys encrypted at rest with org-controlled keys, etc.).
type IOLevel uint8

const (
	// IOPublic — public internet I/O permitted. Lowest tier.
	IOPublic IOLevel = iota
	// IOPrivateNet — egress restricted to allowlisted peers; ingress
	// behind authenticated gateway.
	IOPrivateNet
	// IOPrivateLane — IOPrivateNet + storage encryption at rest with
	// customer-controlled keys; no shared mounts; per-tenant volumes.
	IOPrivateLane
)

// String returns the canonical name for the I/O tier.
func (l IOLevel) String() string {
	switch l {
	case IOPublic:
		return "public"
	case IOPrivateNet:
		return "private_net"
	case IOPrivateLane:
		return "private_lane"
	}
	return "invalid"
}

// Worker is the scheduler's view of a candidate node for a session.
// All fields are populated by the registry from attested measurements
// (see pkg/attestation/nvidia for the GPU side).
type Worker struct {
	ID                 string
	TrustMode          TrustMode
	IOLevel            IOLevel
	KernelManifestRoot [32]byte // root of approved CUDA/CPU kernel manifest
	GPUAttested        bool     // composite NVIDIA attestation verified
	CPUAttested        bool     // SEV-SNP / TDX quote verified
	Online             bool     // worker is reachable + healthy
}

// WorkloadPolicy is the scheduler's view of the policy a workload
// requires of any worker that participates in it.
//
// Each field is a HARD floor — workers below the floor are ineligible.
type WorkloadPolicy struct {
	WorkloadID                  string
	MinTrust                    TrustMode
	MinIO                       IOLevel
	RequireModelConfidentiality bool
	ApprovedKernelRoots         [][32]byte // any-of: worker's KernelManifestRoot must match one
	RequireGPUAttested          bool
	RequireCPUAttested          bool
}

// Eligible reports whether w may participate in a session under p.
// Returns the first failed gate or nil on success.
//
// The decision is fail-closed: any missing or invalid field on either
// side is a rejection. There is no "best effort" mode.
func (p *WorkloadPolicy) Eligible(w Worker) error {
	if p == nil {
		return errors.New("scheduler: nil workload policy")
	}
	if w.ID == "" {
		return errors.New("scheduler: worker missing ID")
	}
	if !w.Online {
		return fmt.Errorf("scheduler: worker %s offline", w.ID)
	}
	if w.TrustMode < p.MinTrust {
		return fmt.Errorf("scheduler: worker %s trust=%s below required %s",
			w.ID, w.TrustMode, p.MinTrust)
	}
	if w.IOLevel < p.MinIO {
		return fmt.Errorf("scheduler: worker %s io=%s below required %s",
			w.ID, w.IOLevel, p.MinIO)
	}
	if p.RequireGPUAttested && !w.GPUAttested {
		return fmt.Errorf("scheduler: worker %s missing GPU attestation", w.ID)
	}
	if p.RequireCPUAttested && !w.CPUAttested {
		return fmt.Errorf("scheduler: worker %s missing CPU attestation", w.ID)
	}
	if p.RequireModelConfidentiality {
		if !w.GPUAttested {
			return fmt.Errorf("scheduler: worker %s confidentiality requires GPU attestation", w.ID)
		}
		if len(p.ApprovedKernelRoots) == 0 {
			return errors.New("scheduler: confidentiality requires approved kernel roots")
		}
		matched := false
		var zero [32]byte
		if w.KernelManifestRoot == zero {
			return fmt.Errorf("scheduler: worker %s missing KernelManifestRoot", w.ID)
		}
		for _, r := range p.ApprovedKernelRoots {
			if r == w.KernelManifestRoot {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("scheduler: worker %s KernelManifestRoot not in approved set", w.ID)
		}
	}
	return nil
}

// PolicySource resolves the WorkloadPolicy for a workload ID. The
// concrete implementation lives in pkg/registry (sibling v0.60); this
// package only depends on the interface.
type PolicySource interface {
	Lookup(workloadID string) (*WorkloadPolicy, error)
}

// Scheduler binds a PolicySource so callers can run eligibility checks
// without threading the source through every call site.
type Scheduler struct {
	src PolicySource
}

// New returns a Scheduler bound to src. src must be non-nil.
func New(src PolicySource) *Scheduler {
	if src == nil {
		panic("scheduler: nil PolicySource")
	}
	return &Scheduler{src: src}
}

// Eligible looks up the policy for workloadID and applies it to w.
// Returns nil iff w is permitted to participate.
func (s *Scheduler) Eligible(w Worker, workloadID string) error {
	p, err := s.src.Lookup(workloadID)
	if err != nil {
		return fmt.Errorf("scheduler: lookup %s: %w", workloadID, err)
	}
	if p == nil {
		return fmt.Errorf("scheduler: no policy for workload %s", workloadID)
	}
	return p.Eligible(w)
}

// StaticPolicySource is an in-memory PolicySource. Useful for tests and
// for the legacy single-policy deployment mode where the policy is
// loaded from config at startup.
type StaticPolicySource struct {
	policies map[string]*WorkloadPolicy
}

// NewStaticPolicySource constructs a StaticPolicySource from a map.
func NewStaticPolicySource(m map[string]*WorkloadPolicy) *StaticPolicySource {
	cp := make(map[string]*WorkloadPolicy, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return &StaticPolicySource{policies: cp}
}

// Lookup returns the policy for workloadID or an error if absent.
func (s *StaticPolicySource) Lookup(workloadID string) (*WorkloadPolicy, error) {
	p, ok := s.policies[workloadID]
	if !ok {
		return nil, fmt.Errorf("workload %s not registered", workloadID)
	}
	return p, nil
}
