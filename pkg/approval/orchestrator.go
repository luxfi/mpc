package approval

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Orchestrator collects ApprovalSignatures from N independent providers,
// returning a bundle once `threshold` valid signatures arrive. It does not
// itself decide which approver uses which provider — that mapping is
// supplied by the caller via ApproverBinding.
//
// One Orchestrator covers all providers; pass them at construction. Each
// approverID has exactly one binding (provider + per-provider config) so
// the same human signs in exactly one way.
type Orchestrator struct {
	providers map[string]ApprovalProvider // providerName -> provider
	bindings  map[string]ApproverBinding  // approverID -> binding
}

// ApproverBinding ties a human (approverID) to a provider and the
// provider-specific identity that provider knows them by.
//
// ProviderName must match a registered ApprovalProvider's Provider() return.
type ApproverBinding struct {
	ApproverID   string
	ProviderName string
}

// NewOrchestrator builds an Orchestrator with the given providers indexed by
// Provider().
func NewOrchestrator(providers []ApprovalProvider) *Orchestrator {
	idx := make(map[string]ApprovalProvider, len(providers))
	for _, p := range providers {
		idx[p.Provider()] = p
	}
	return &Orchestrator{
		providers: idx,
		bindings:  make(map[string]ApproverBinding),
	}
}

// Bind registers an approver -> provider mapping. Calling Bind twice for
// the same approverID overwrites; this is intentional — rotation is one
// operation.
func (o *Orchestrator) Bind(b ApproverBinding) error {
	if _, ok := o.providers[b.ProviderName]; !ok {
		return fmt.Errorf("approval/orchestrator: unknown provider %q", b.ProviderName)
	}
	if b.ApproverID == "" {
		return errors.New("approval/orchestrator: approver_id required")
	}
	o.bindings[b.ApproverID] = b
	return nil
}

// CollectApprovals dispatches the intent to every requiredApprover's bound
// provider in parallel, returns when `threshold` succeed, or the context
// expires. On context cancellation, in-flight provider calls are cancelled
// (each provider receives the cancelled child context and is expected to
// return promptly).
//
// Returns the bundle of successful signatures (>= threshold) or an error
// describing why the threshold could not be met.
//
// Duplicate approvers are deduplicated. threshold > len(requiredApprovers)
// is rejected — a 3-of-2 ask is meaningless.
func (o *Orchestrator) CollectApprovals(
	ctx context.Context,
	intent CanonicalIntent,
	requiredApprovers []string,
	threshold int,
) ([]ApprovalSignature, error) {
	if threshold <= 0 {
		return nil, errors.New("approval/orchestrator: threshold must be > 0")
	}
	uniq := dedupe(requiredApprovers)
	if threshold > len(uniq) {
		return nil, fmt.Errorf("approval/orchestrator: threshold %d > approvers %d", threshold, len(uniq))
	}

	type result struct {
		sig ApprovalSignature
		err error
	}

	dispatchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultsCh := make(chan result, len(uniq))
	var wg sync.WaitGroup
	for _, approverID := range uniq {
		binding, ok := o.bindings[approverID]
		if !ok {
			resultsCh <- result{err: fmt.Errorf("approval/orchestrator: approver %q not bound", approverID)}
			continue
		}
		provider, ok := o.providers[binding.ProviderName]
		if !ok {
			resultsCh <- result{err: fmt.Errorf("approval/orchestrator: provider %q for approver %q not registered", binding.ProviderName, approverID)}
			continue
		}
		wg.Add(1)
		go func(approverID string, prov ApprovalProvider) {
			defer wg.Done()
			sig, err := prov.ApproveIntent(dispatchCtx, approverID, intent)
			resultsCh <- result{sig: sig, err: err}
		}(approverID, provider)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	collected := make([]ApprovalSignature, 0, threshold)
	failures := make([]error, 0)
	for res := range resultsCh {
		if res.err != nil {
			failures = append(failures, res.err)
			continue
		}
		collected = append(collected, res.sig)
		if len(collected) >= threshold {
			cancel() // best-effort cancel any still-pending providers
			return collected, nil
		}
	}

	return nil, fmt.Errorf("approval/orchestrator: threshold %d not met (got %d successes, %d failures: %v)", threshold, len(collected), len(failures), failures)
}

// VerifyBundle checks every signature in `bundle` against its provider and
// the canonical intent. Returns true iff every signature verifies AND the
// distinct approver count is >= threshold.
//
// "Approver count" deduplicates (approverID, provider) pairs — a single
// approver can't satisfy multiple slots even if they sign twice via two
// providers (defensive against an approver who somehow has multiple
// bindings).
func (o *Orchestrator) VerifyBundle(ctx context.Context, intent CanonicalIntent, bundle []ApprovalSignature, threshold int) (bool, error) {
	if threshold <= 0 {
		return false, errors.New("approval/orchestrator: threshold must be > 0")
	}
	seen := make(map[string]struct{}, len(bundle))
	for _, sig := range bundle {
		provider, ok := o.providers[sig.Provider]
		if !ok {
			return false, fmt.Errorf("approval/orchestrator: provider %q not registered", sig.Provider)
		}
		ok, err := provider.VerifyApproval(ctx, intent, sig)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		key := sig.ApproverID + "|" + sig.Provider
		seen[key] = struct{}{}
	}
	return len(seen) >= threshold, nil
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
