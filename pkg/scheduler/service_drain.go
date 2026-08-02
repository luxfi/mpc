// Drain — refuse a service drain unless EVERY remaining worker passes
// the policy gate. A drain that lowers the eligible-worker count below
// the workload's threshold is rejected; a drain that would force a
// session to land on an ineligible worker is rejected.
//
// This is the operational complement to Eligible(): it answers "can we
// drain node X right now without weakening the trust posture below
// what the workload requires?".
package scheduler

import (
	"errors"
	"fmt"
)

// ErrInsufficientTrust is returned when a drain (or sign authorization)
// would proceed on a worker set below the workload's required trust
// floor. Callers may errors.Is against this sentinel.
var ErrInsufficientTrust = errors.New("scheduler: insufficient trust for workload")

// DrainRequest describes a proposed drain. Threshold is the minimum
// number of eligible workers the workload requires to remain
// operational AFTER the drain.
type DrainRequest struct {
	NodeID     string
	WorkloadID string
	Workers    []Worker // current worker set, including the one to drain
	Threshold  int      // min eligible after drain (e.g. t+1 for t-of-n MPC)
}

// AuthorizeDrain returns nil iff draining req.NodeID is safe for the
// workload. Otherwise returns a wrapped ErrInsufficientTrust describing
// the failed gate.
//
// Algorithm:
//  1. Resolve the WorkloadPolicy.
//  2. Filter Workers by Eligible(p) AND ID != NodeID.
//  3. If len(remaining) < Threshold → reject.
//
// Workers that are already ineligible BEFORE the drain are not counted —
// the drain cannot improve their state, but it must not also remove a
// worker the policy still depended on.
func (s *Scheduler) AuthorizeDrain(req DrainRequest) error {
	if req.NodeID == "" {
		return errors.New("scheduler: drain missing node ID")
	}
	if req.WorkloadID == "" {
		return errors.New("scheduler: drain missing workload ID")
	}
	if req.Threshold <= 0 {
		return errors.New("scheduler: drain threshold must be positive")
	}

	p, err := s.src.Lookup(req.WorkloadID)
	if err != nil {
		return fmt.Errorf("scheduler: drain lookup %s: %w", req.WorkloadID, err)
	}
	if p == nil {
		return fmt.Errorf("scheduler: drain no policy for %s", req.WorkloadID)
	}

	eligible := 0
	for _, w := range req.Workers {
		if w.ID == req.NodeID {
			continue // the worker being drained
		}
		if err := p.Eligible(w); err != nil {
			continue // already ineligible — does not count toward threshold
		}
		eligible++
	}

	if eligible < req.Threshold {
		return fmt.Errorf("%w: workload=%s would have %d eligible workers, need %d",
			ErrInsufficientTrust, req.WorkloadID, eligible, req.Threshold)
	}
	return nil
}

// AuthorizeSession is the per-sign analogue: given the candidate worker
// set and the workload, return the subset that may participate. Returns
// ErrInsufficientTrust if fewer than min workers pass the gate.
//
// The order of the returned slice matches the input order — callers
// that depend on stable selection (party-ID assignment in MPC) get
// deterministic results.
func (s *Scheduler) AuthorizeSession(workloadID string, candidates []Worker, min int) ([]Worker, error) {
	if workloadID == "" {
		return nil, errors.New("scheduler: session missing workload ID")
	}
	if min <= 0 {
		return nil, errors.New("scheduler: session min must be positive")
	}

	p, err := s.src.Lookup(workloadID)
	if err != nil {
		return nil, fmt.Errorf("scheduler: session lookup %s: %w", workloadID, err)
	}
	if p == nil {
		return nil, fmt.Errorf("scheduler: session no policy for %s", workloadID)
	}

	out := make([]Worker, 0, len(candidates))
	for _, w := range candidates {
		if err := p.Eligible(w); err == nil {
			out = append(out, w)
		}
	}
	if len(out) < min {
		return nil, fmt.Errorf("%w: workload=%s eligible=%d min=%d",
			ErrInsufficientTrust, workloadID, len(out), min)
	}
	return out, nil
}
