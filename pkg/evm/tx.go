package evm

import (
	"context"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// SignTx assembles a broadcast-ready signed transaction. It computes the digest
// the transaction is signed over for chainID, asks the signer for a threshold
// signature over that digest, applies it, and — before returning — recovers the
// sender and checks it is the signer's own account. A wrong recovery id would
// bind the transaction to a different account and spend from nobody; that is
// caught here and refused, never broadcast.
//
// chainID is the EVM chain id (Lux mainnet is 96369). The digest and the applied
// signature both follow the transaction's own type — legacy, EIP-155, or typed —
// because the signer returned by LatestSignerForChainID handles all of them.
func SignTx(ctx context.Context, s Signer, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("evm: chain id must be positive, got %v", chainID)
	}
	signer := types.LatestSignerForChainID(chainID)
	digest := signer.Hash(tx)

	sig, err := s.Sign(ctx, digest[:])
	if err != nil {
		return nil, err
	}

	signed, err := tx.WithSignature(signer, sig.Bytes())
	if err != nil {
		return nil, fmt.Errorf("evm: apply signature: %w", err)
	}

	from, err := types.Sender(signer, signed)
	if err != nil {
		return nil, fmt.Errorf("evm: recover sender: %w", err)
	}
	if from != s.Account() {
		return nil, fmt.Errorf("evm: signature binds tx to %s, want %s", from, s.Account())
	}
	return signed, nil
}

// Digest returns the 32-byte value a transaction is signed over for chainID —
// the input to hand an MPC signing round when a caller wants to sign and
// assemble in two separate steps (build the digest here, sign it through the
// quorum, then Apply). Signing and assembling in one call is SignTx.
func Digest(tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("evm: chain id must be positive, got %v", chainID)
	}
	h := types.LatestSignerForChainID(chainID).Hash(tx)
	return h[:], nil
}

// Apply attaches a signature obtained out of band (from an MPC signing round
// over Digest(tx)) and verifies it binds the transaction to want. It is the
// second half of the two-step path whose first half is Digest.
func Apply(tx *types.Transaction, chainID *big.Int, sig Signature, want common.Address) (*types.Transaction, error) {
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("evm: chain id must be positive, got %v", chainID)
	}
	signer := types.LatestSignerForChainID(chainID)
	signed, err := tx.WithSignature(signer, sig.Bytes())
	if err != nil {
		return nil, fmt.Errorf("evm: apply signature: %w", err)
	}
	from, err := types.Sender(signer, signed)
	if err != nil {
		return nil, fmt.Errorf("evm: recover sender: %w", err)
	}
	if from != want {
		return nil, fmt.Errorf("evm: signature binds tx to %s, want %s", from, want)
	}
	return signed, nil
}
