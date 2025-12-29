package mpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/luxfi/mpc/pkg/policy"
	"github.com/luxfi/mpc/pkg/risk"
)

func TestSignGate_NilGate(t *testing.T) {
	var g *mpc.SignGate
	_, err := g.AuthorizeSign(context.Background(), &intent.CanonicalIntent{})
	if err == nil {
		t.Fatal("expected error from nil gate")
	}
}

func TestSignGate_NilIntent(t *testing.T) {
	wr := policy.NewMemWalletRegistry()
	ks := policy.NewMemApprovalKeyset()
	rp := risk.NewInternalAllowlistProvider()
	ps := policy.NewMemPolicyStore()
	v := policy.NewLocalVerifier(wr, ks, rp, ps)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	g := mpc.NewSignGate("node0", priv, v, nil)
	if _, err := g.AuthorizeSign(context.Background(), nil); err == nil {
		t.Fatal("expected error from nil intent")
	}
}

func TestSignGate_BlocksAndPropagatesUnderlying(t *testing.T) {
	wr := policy.NewMemWalletRegistry()
	ks := policy.NewMemApprovalKeyset()
	rp := risk.NewInternalAllowlistProvider()
	ps := policy.NewMemPolicyStore()
	v := policy.NewLocalVerifier(wr, ks, rp, ps)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sink := mpc.NewMemAttestationSink()
	g := mpc.NewSignGate("node0", priv, v, sink)

	// Structurally valid intent that fails on unknown wallet.
	ci := &intent.CanonicalIntent{
		IntentVersion: intent.IntentVersion,
		SessionID:     "s1",
		WalletID:      "ghost",
		WalletTier:    intent.TierWarm,
		Chain:         "eip155:1",
		From:          "0xfrom",
		To:            "0xto",
		Amount:        "1",
		PolicyID:      "p",
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	att, err := g.AuthorizeSign(context.Background(), ci)
	if !errors.Is(err, mpc.ErrSignBlocked) {
		t.Fatalf("expected ErrSignBlocked, got %v", err)
	}
	if !errors.Is(err, policy.ErrUnknownWallet) {
		t.Fatalf("expected wrapped ErrUnknownWallet, got %v", err)
	}
	if att.Verdict != "reject" {
		t.Fatalf("expected reject attestation, got %s", att.Verdict)
	}
	if got := sink.All(); len(got) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(got))
	}
}
