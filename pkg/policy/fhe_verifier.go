// Per-node FHE policy verifier — sibling of LocalVerifier.
//
// FHEVerifier reads an FHE-encoded policy from F-Chain, evaluates the
// policy circuit homomorphically against the encrypted intent fields,
// threshold-decrypts the result via the M-Chain MPC committee, and fails
// closed if the verdict is not unambiguously "allow".
//
// The plaintext policy never leaves F-Chain. The plaintext intent never
// leaves the wallet. M-Chain nodes only ever see ciphertexts and the
// final decrypted bool — which is exactly what they need to decide
// whether to release a partial signature share.
package policy

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
)

// FHEVerifier-side errors. Distinct from LocalVerifier errors so the audit
// log can categorize FHE-path failures separately.
var (
	ErrFHEPolicyEval     = errors.New("fhe-verifier: policy evaluation failed")
	ErrFHEThresholdDec   = errors.New("fhe-verifier: threshold decryption failed")
	ErrFHEVerdictDeny    = errors.New("fhe-verifier: encrypted policy denied")
	ErrFHEClientRequired = errors.New("fhe-verifier: F-Chain client not configured")
	ErrFHEDecRequired    = errors.New("fhe-verifier: threshold decryptor not configured")
)

// FChainClient submits an encrypted intent to F-Chain's PolicyVault and
// returns the encrypted boolean verdict.
//
// Implementations are responsible for: (a) fetching the network public key,
// (b) bit-encrypting Amount/DestinationHash/VelocityWindow under that key,
// (c) calling PolicyVault.evaluateLatest, (d) returning the encrypted
// result bytes.
//
// The verifier does not assume any particular FHE scheme — only that the
// returned bytes can be threshold-decrypted by ThresholdDecryptor.
type FChainClient interface {
	EvaluateLatest(
		ctx context.Context,
		walletID string,
		amount *big.Int,
		destinationHash [32]byte,
		velocityWindow *big.Int,
	) (encResult []byte, err error)
}

// PlanProvider is the rule-engine path: a precompiled, cached RulePlan
// (compiled from the YAML stored on F-Chain PolicyVault) is evaluated
// locally against per-intent encrypted inputs. The provider returns the
// same opaque encrypted-verdict bytes the FChainClient path returns, so
// the downstream ThresholdDecryptor sees one wire shape.
//
// PlanProvider is OPTIONAL. When wired, the verifier prefers it over
// FChainClient — local evaluation avoids one network hop per intent
// and benefits from the plan cache (compile-once-per-policy-version).
//
// Concrete implementations live in luxfi/fhe (which owns the
// dependencies on fhe.Parameters / BootstrapKey / *Engine). Keeping
// the interface here means luxfi/mpc does not depend on luxfi/fhe.
type PlanProvider interface {
	// EvaluatePlan compiles+caches the policy referenced by
	// (policyID, policyHash), encrypts the intent fields under the
	// network public key, runs the plan, and returns the encrypted
	// verdict in the same opaque byte shape as FChainClient.
	EvaluatePlan(
		ctx context.Context,
		policyID string,
		policyHash [32]byte,
		walletID string,
		amount *big.Int,
		destinationHash [32]byte,
		velocityWindow *big.Int,
	) (encResult []byte, err error)
}

// ThresholdDecryptor performs threshold decryption of an FHE ciphertext
// produced by FChainClient. In production this is wired to the M-Chain
// MPC committee running luxfi/lattice's t-of-n threshold protocol.
//
// Errors are treated as "deny" by the verifier — failing-closed is the
// only safe posture when the committee cannot reach consensus on a bit.
type ThresholdDecryptor interface {
	Decrypt(ctx context.Context, ciphertext []byte) (bool, error)
}

// VelocityProvider returns the running spend total for a wallet over the
// policy's velocity window. M-Chain reads this from local state (Postgres
// + Valkey) and passes it to F-Chain encrypted; F-Chain does the strict
// less-than check homomorphically against the encrypted cap.
type VelocityProvider interface {
	WindowSpend(ctx context.Context, walletID string, asset string) (*big.Int, error)
}

// FHEVerifier executes the FHE-policy gate. It is the encrypted-policy
// counterpart to LocalVerifier.
//
// Field semantics:
//   - WalletRegistry: required. Wallet existence + tier check.
//   - Velocity: required. Per-wallet running spend totals.
//   - Decryptor: required. Threshold-decrypts the encrypted verdict.
//   - Plan: optional, preferred when set. Local rule-engine path:
//     plan compiled from F-Chain YAML, evaluated against per-intent
//     encrypted inputs. Returns the same opaque verdict bytes as the
//     FChainClient path so the Decryptor sees one wire shape.
//   - FChain: required when Plan is nil. Remote PolicyVault evaluation.
//     If both Plan and FChain are set, Plan wins.
//   - DecryptTimeout: optional. Caps how long the verifier waits on the
//     threshold-decrypt round before failing closed. Zero = no cap.
type FHEVerifier struct {
	WalletRegistry WalletRegistry
	FChain         FChainClient
	Plan           PlanProvider
	Decryptor      ThresholdDecryptor
	Velocity       VelocityProvider
	DecryptTimeout time.Duration
	// Now overrides time.Now for tests. Nil = real clock.
	Now func() time.Time
}

// NewFHEVerifier wires the verifier dependencies for the F-Chain
// remote evaluation path. All fields except Now and DecryptTimeout
// are required; passing nil panics at first use.
func NewFHEVerifier(
	wr WalletRegistry,
	fc FChainClient,
	td ThresholdDecryptor,
	vp VelocityProvider,
) *FHEVerifier {
	return &FHEVerifier{
		WalletRegistry: wr,
		FChain:         fc,
		Decryptor:      td,
		Velocity:       vp,
	}
}

// NewFHEVerifierWithPlan wires the verifier for the local rule-engine
// plan path. Plan compiles + caches the policy YAML once per version
// and evaluates against per-intent encrypted inputs without an extra
// network hop to F-Chain. Threshold decryption still runs on the
// committee.
func NewFHEVerifierWithPlan(
	wr WalletRegistry,
	pp PlanProvider,
	td ThresholdDecryptor,
	vp VelocityProvider,
) *FHEVerifier {
	return &FHEVerifier{
		WalletRegistry: wr,
		Plan:           pp,
		Decryptor:      td,
		Velocity:       vp,
	}
}

func (v *FHEVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify runs the FHE-policy gate against ci. On success, returns nil and
// ci may be passed to the threshold sign. On any failure, returns the
// first error encountered.
//
// The check order is deliberate: cheap structural + registry checks first
// so that an obviously-bad intent never reaches the (expensive) FHE round.
//
// Path selection:
//   - If Plan is set, the local rule-engine path runs (compiled-once
//     RulePlan, evaluated locally against encrypted inputs).
//   - Otherwise FChain.EvaluateLatest is called.
//
// Both paths return opaque encrypted-verdict bytes that the Decryptor
// threshold-decrypts to a final bool.
func (v *FHEVerifier) Verify(ctx context.Context, ci *intent.CanonicalIntent) error {
	if v.Plan == nil && v.FChain == nil {
		return ErrFHEClientRequired
	}
	if v.Decryptor == nil {
		return ErrFHEDecRequired
	}

	// 0. Structural validation — cheap, catches malformed payloads.
	if err := ci.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIntent, err)
	}

	// 1. Wallet registry — known wallet, expected tier.
	w, ok := v.WalletRegistry.Get(ci.WalletID)
	if !ok {
		return ErrUnknownWallet
	}
	if w.Tier != ci.WalletTier {
		return fmt.Errorf("%w: registry=%s intent=%s", ErrTierMismatch, w.Tier, ci.WalletTier)
	}

	// 2. Expiry — fail before anything expensive.
	if v.now().After(ci.ExpiresAt) {
		return ErrExpiredIntent
	}

	// 3. Encode intent fields. Amount is a decimal string; destination is
	// the keccak/sha256 of the To address; velocity is the running window.
	amount, ok := new(big.Int).SetString(ci.Amount, 10)
	if !ok {
		return fmt.Errorf("%w: invalid amount %q", ErrInvalidIntent, ci.Amount)
	}
	velocity, err := v.Velocity.WindowSpend(ctx, ci.WalletID, ci.Asset)
	if err != nil {
		return fmt.Errorf("fhe-verifier: velocity: %w", err)
	}

	var destHash [32]byte
	copy(destHash[:], ci.CalldataHash[:]) // M-Chain hashes the To address into CalldataHash for non-contract calls; bridge code lives upstream.

	// 4. Policy evaluation — homomorphic, no plaintext leakage.
	//    Prefer the local rule-engine plan path when wired; fall
	//    back to the F-Chain remote evaluation otherwise.
	evalCtx := ctx
	if v.DecryptTimeout > 0 {
		var cancel context.CancelFunc
		evalCtx, cancel = context.WithTimeout(ctx, v.DecryptTimeout)
		defer cancel()
	}
	var (
		encResult []byte
	)
	if v.Plan != nil {
		encResult, err = v.Plan.EvaluatePlan(
			evalCtx,
			ci.PolicyID,
			ci.PolicyHash,
			ci.WalletID,
			amount,
			destHash,
			velocity,
		)
	} else {
		encResult, err = v.FChain.EvaluateLatest(evalCtx, ci.WalletID, amount, destHash, velocity)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFHEPolicyEval, err)
	}

	// 5. Threshold decryption via M-Chain MPC committee. Errors fail closed.
	allowed, err := v.Decryptor.Decrypt(evalCtx, encResult)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFHEThresholdDec, err)
	}
	if !allowed {
		return ErrFHEVerdictDeny
	}
	return nil
}
