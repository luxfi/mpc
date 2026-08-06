package mpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/taproot"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/mpc/pkg/address"
)

// ed25519Keygen runs the keygen the daemon's Ed25519 session runs, then puts
// every share through the CBOR codec the daemon actually stores it with.
//
// The storage round trip is part of the ceremony on purpose. Signing does not
// use the config keygen produced in memory — it uses whatever came back out of
// the kvstore. A codec that dropped or mangled a field would produce a wallet
// that looked correct at keygen and could not sign afterwards, which is exactly
// the class of failure these tests exist to rule out.
func ed25519Keygen(t *testing.T, ids []party.ID, threshold int, sessionID []byte) map[party.ID]*frost.Config {
	t.Helper()

	raw := runCeremony(t, ids, sessionID, func(id party.ID) protocol.StartFunc {
		// Mirrors frostKeygenSession.Init().
		return ed25519KeygenStart(id, ids, threshold)
	})

	configs := make(map[party.ID]*frost.Config, len(raw))
	for id, res := range raw {
		cfg, ok := res.(*frost.Config)
		require.True(t, ok, "party %s: want *frost.Config, got %T", id, res)

		// Mirrors frostKeygenSession.publishResult() writing the share, and
		// newFROSTSigningSession reading it back.
		blob, err := MarshalEd25519Config(cfg)
		require.NoError(t, err, "party %s: share did not marshal", id)
		restored, err := UnmarshalEd25519Config(blob)
		require.NoError(t, err, "party %s: share did not survive storage", id)

		configs[id] = restored
	}
	return configs
}

// publishedPublicKey extracts the key exactly as frostKeygenSession.publishResult
// does, and asserts every party agrees on it. Disagreement would mean the ring
// had minted several different wallets while believing it had minted one.
func publishedPublicKey(t *testing.T, configs map[party.ID]*frost.Config, ids []party.ID) []byte {
	t.Helper()

	pub, err := configs[ids[0]].PublicKey.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, pub, 32)

	for _, id := range ids {
		other, err := configs[id].PublicKey.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, pub, other, "party %s disagrees on the wallet public key", id)
	}
	return pub
}

// TestEd25519WalletAddressIsSpendable is the test this change exists to pass.
//
// It runs the daemon's real keygen, stores and reloads the shares with the
// daemon's real codec, derives the address with the daemon's real derivation,
// then decodes that address back to bytes and verifies a threshold signature
// against THOSE bytes with the standard library. Verifying against the config's
// public key would prove only that the ceremony is self-consistent; verifying
// against the address proves that the specific string a customer would be handed
// is one the ring can sign for. That is the only property that means anything to
// someone who has just deposited into it.
func TestEd25519WalletAddressIsSpendable(t *testing.T) {
	ids := ceremonyParties() // node-a, node-b, node-c
	const threshold = 1      // degree 1 => any 2 of the 3 can sign

	configs := ed25519Keygen(t, ids, threshold, []byte("spendable-keygen"))
	pub := publishedPublicKey(t, configs, ids)

	// The address mpcd would hand a customer.
	solAddress, err := address.Solana(pub)
	require.NoError(t, err, "keygen must produce a key that yields a Solana address")
	require.NotEmpty(t, solAddress)

	// Go back the way a customer's funds do: from the address string to the key
	// the chain will check signatures against. Everything below verifies against
	// this, never against the config.
	addressKey, err := base58.Decode(solAddress)
	require.NoError(t, err, "the published address must base58-decode")
	require.Len(t, addressKey, ed25519.PublicKeySize)
	require.Equal(t, pub, addressKey, "the address must encode the wallet key and nothing else")

	// A message that is deliberately not 32 bytes. PureEdDSA signs the message
	// itself, so any pre-hashing on the signing path would sign a digest instead
	// and this would fail — which is precisely how the old BIP-340 path, which
	// SHA-256'd anything that was not already 32 bytes, would be caught.
	message := []byte("transfer 1 SOL to a customer; this message is longer than 32 bytes")
	require.NotEqual(t, 32, len(message))

	signers := ids[:threshold+1] // a strict subset: Lagrange interpolation is real
	rawSign := runCeremony(t, signers, []byte("spendable-sign"), func(id party.ID) protocol.StartFunc {
		// Mirrors frostSigningSession.Init().
		return ed25519SignStart(configs[id], signers, message)
	})

	// SignEd25519 resolves to a value, not a pointer.
	sig, ok := rawSign[signers[0]].(frost.Ed25519Signature)
	require.True(t, ok, "want frost.Ed25519Signature, got %T", rawSign[signers[0]])

	encoded, err := sig.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, encoded, ed25519.SignatureSize)

	// THE assertion: the standard library, the address, the message.
	require.True(t, ed25519.Verify(ed25519.PublicKey(addressKey), message, encoded),
		"a signature from the ring must verify against the address mpcd publishes")

	// Emit the evidence rather than leaving it implicit in a green tick.
	t.Logf("sol_address       = %s", solAddress)
	t.Logf("pubkey (from addr)= %x", addressKey)
	t.Logf("signature R||S    = %x", encoded)
	t.Logf("ed25519.Verify    = PASS (%d-of-%d ring, signers %v)", threshold+1, len(ids), signers)

	// Every signer subset must work, or the wallet is spendable only by luck.
	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			subset := []party.ID{ids[i], ids[j]}
			t.Run("subset_"+string(subset[0])+"_"+string(subset[1]), func(t *testing.T) {
				raw := runCeremony(t, subset, []byte("spendable-subset"), func(id party.ID) protocol.StartFunc {
					return ed25519SignStart(configs[id], subset, message)
				})
				s, ok := raw[subset[0]].(frost.Ed25519Signature)
				require.True(t, ok)
				enc, err := s.MarshalBinary()
				require.NoError(t, err)
				require.True(t, ed25519.Verify(ed25519.PublicKey(addressKey), message, enc),
					"subset %v cannot sign for the published address", subset)
			})
		}
	}
}

// TestEd25519SignsRealisticPayloads covers the two payload shapes the wallet
// actually sends: a Solana transaction message, which is hundreds of bytes, and
// a TON cell hash, which is exactly 32. The 32-byte case is the dangerous one —
// it is the length the old signing path passed through untouched while hashing
// everything else, so a pre-hash bug would hide behind it.
func TestEd25519SignsRealisticPayloads(t *testing.T) {
	ids := ceremonyParties()
	const threshold = 1

	configs := ed25519Keygen(t, ids, threshold, []byte("payloads-keygen"))
	pub := publishedPublicKey(t, configs, ids)
	signers := ids[:threshold+1]

	tonCellHash := sha256.Sum256([]byte("ton transfer body cell"))
	solanaTxMessage := make([]byte, 512)
	for i := range solanaTxMessage {
		solanaTxMessage[i] = byte(i)
	}

	for name, message := range map[string][]byte{
		"solana_transaction_message": solanaTxMessage,
		"ton_cell_hash_32_bytes":     tonCellHash[:],
		"empty_message":              {},
	} {
		t.Run(name, func(t *testing.T) {
			raw := runCeremony(t, signers, []byte("payloads-sign-"+name), func(id party.ID) protocol.StartFunc {
				return ed25519SignStart(configs[id], signers, message)
			})
			sig, ok := raw[signers[0]].(frost.Ed25519Signature)
			require.True(t, ok)
			encoded, err := sig.MarshalBinary()
			require.NoError(t, err)
			require.True(t, ed25519.Verify(ed25519.PublicKey(pub), message, encoded),
				"ring must sign %s as-is, without hashing it first", name)
		})
	}
}

// TestTaprootKeygenCannotReachTheEd25519Path is the regression guard for the bug
// this change removes, and it asserts the barrier that actually holds.
//
// The barrier is provenance, expressed as a type. FROST over secp256k1 finishes
// as *frost.TaprootConfig; the Ed25519 keygen session accepts *frost.Config and
// nothing else, and refuses any other concrete type rather than reaching into
// it. That check is deterministic, which the curve check on the resulting bytes
// is not — see TestSolanaGateIsABackstopNotABarrier.
func TestTaprootKeygenCannotReachTheEd25519Path(t *testing.T) {
	ids := ceremonyParties()

	raw := runCeremony(t, ids, []byte("taproot-regression"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenTaproot(id, ids, 1)
	})

	cfg, ok := raw[ids[0]].(*frost.TaprootConfig)
	require.True(t, ok, "want *frost.TaprootConfig, got %T", raw[ids[0]])

	// The premise: 32 bytes, so no length test can tell it apart from Ed25519.
	taprootPub := []byte(cfg.PublicKey)
	require.Len(t, taprootPub, 32)
	_, err := curve.Secp256k1{}.LiftX(taprootPub)
	require.NoError(t, err, "this key really is a secp256k1 x-only key")

	// The barrier: a Taproot result is not a *frost.Config, so the type
	// assertion in frostKeygenSession.handleProtocolMessages rejects it.
	_, isEd25519Config := raw[ids[0]].(*frost.Config)
	require.False(t, isEd25519Config,
		"a Taproot ceremony must not satisfy the Ed25519 session's result type")

	// And the library refuses to sign an Ed25519 signature with a secp256k1
	// config even if one were somehow assembled, so the wrong curve cannot reach
	// a signer by any route.
	lifted, err := curve.Secp256k1{}.LiftX(taprootPub)
	require.NoError(t, err)
	shares := make(map[party.ID]curve.Point, len(cfg.VerificationShares))
	for id, p := range cfg.VerificationShares {
		shares[id] = p
	}
	secpConfig := &frost.Config{
		ID:                 cfg.ID,
		Threshold:          cfg.Threshold,
		PrivateShare:       cfg.PrivateShare,
		PublicKey:          lifted,
		VerificationShares: party.NewPointMap(shares),
	}
	_, err = frost.SignEd25519(secpConfig, ids[:2], []byte("withdraw"))(nil)
	require.Error(t, err, "SignEd25519 must refuse a secp256k1 config")
}

// TestSolanaGateIsABackstopNotABarrier measures the property the address check
// really has, rather than the one it is tempting to assume.
//
// A BIP-340 x-only key is a 32-byte string. Roughly half of those decode to some
// edwards25519 point, and one in eight of those lands in the prime-order
// subgroup, so about one secp256k1 key in sixteen is ALSO a perfectly valid
// Ed25519 public key and the curve check accepts it. This is not a defect in the
// check — no function of the bytes alone can do better, because such a key is
// genuinely both. It is the reason provenance is the primary defence and this
// gate is only a backstop.
//
// The test asserts the rate is high enough to be worth having and explicitly
// tolerates the coincidences, so it is not flaky and does not encourage anyone
// to rely on it as a guarantee.
func TestSolanaGateIsABackstopNotABarrier(t *testing.T) {
	const samples = 2048

	secpKeys, refused := 0, 0
	buf := make([]byte, 32)
	for i := 0; i < samples*4 && secpKeys < samples; i++ {
		_, err := rand.Read(buf)
		require.NoError(t, err)
		if _, err := (curve.Secp256k1{}).LiftX(buf); err != nil {
			continue // not a secp256k1 x-only key; not the case under study
		}
		secpKeys++

		addr, err := address.Solana(buf)
		if err != nil {
			require.ErrorIs(t, err, address.ErrNotEd25519)
			require.Empty(t, addr, "an error must never be accompanied by an address")
			refused++
			continue
		}
		// Accepted. That is only sound because these bytes really are a valid
		// Ed25519 key too — assert that, so an accept can never mean the check
		// simply did not run.
		require.NoError(t, (curve.Ed25519{}).NewPoint().UnmarshalBinary(buf),
			"the gate accepted %x without it being a valid Ed25519 point", buf)
	}
	require.Equal(t, samples, secpKeys, "did not gather enough secp256k1 keys")

	rate := float64(refused) / float64(secpKeys)
	t.Logf("address gate refused %d/%d secp256k1 x-only keys (%.1f%%); the rest are genuinely valid Ed25519 keys too",
		refused, secpKeys, rate*100)

	// Expected ~15/16 = 93.75%. A wide band keeps this a property test, not a
	// coin-flip. If this ever drops near zero the gate has stopped working.
	require.Greater(t, rate, 0.85, "the curve gate should refuse the large majority of secp256k1 keys")
	require.Less(t, rate, 1.0, "if it refused all of them the sample is not what this test claims to measure")
}

// TestTaprootSignatureNeverSatisfiesEd25519 keeps the fund-loss proof itself
// alive: the ring genuinely signs, and the standard library genuinely rejects
// it. If this ever passes, the two schemes have been confused again.
func TestTaprootSignatureNeverSatisfiesEd25519(t *testing.T) {
	ids := ceremonyParties()

	rawKeygen := runCeremony(t, ids, []byte("taproot-sig-keygen"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenTaproot(id, ids, 1)
	})
	configs := make(map[party.ID]*frost.TaprootConfig, len(rawKeygen))
	for id, res := range rawKeygen {
		cfg, ok := res.(*frost.TaprootConfig)
		require.True(t, ok, "party %s: want *frost.TaprootConfig, got %T", id, res)
		configs[id] = cfg
	}

	signers := ids[:2]
	digest := sha256.Sum256([]byte("withdraw 1 SOL"))

	rawSign := runCeremony(t, signers, []byte("taproot-sig-sign"), func(id party.ID) protocol.StartFunc {
		return frost.SignTaproot(configs[id], signers, digest[:])
	})
	sig, ok := rawSign[signers[0]].(taproot.Signature)
	require.True(t, ok)

	pub := []byte(configs[ids[0]].PublicKey)

	// It is a valid signature — under BIP-340.
	require.True(t, taproot.PublicKey(pub).Verify(sig, digest[:]),
		"the ceremony must really produce a valid BIP-340 signature")

	// And worthless under Ed25519, which is what Solana checks.
	require.False(t, ed25519.Verify(ed25519.PublicKey(pub), digest[:], sig),
		"a BIP-340 signature must never satisfy Ed25519 verification")
}

// TestGenericFrostSignatureIsNotSpendable closes the remaining trap in the
// library's API. frost.Sign over an Ed25519 config returns 64 bytes in the same
// shape as an Ed25519 signature, but its challenge is BLAKE3 and its S is
// big-endian, so no chain will accept it. Only SignEd25519 may be used, and this
// test fails if anyone reaches for the generic entry point.
func TestGenericFrostSignatureIsNotSpendable(t *testing.T) {
	ids := ceremonyParties()
	const threshold = 1

	configs := ed25519Keygen(t, ids, threshold, []byte("generic-keygen"))
	pub := publishedPublicKey(t, configs, ids)
	signers := ids[:threshold+1]

	message := []byte("withdraw 1 SOL")

	rawSign := runCeremony(t, signers, []byte("generic-sign"), func(id party.ID) protocol.StartFunc {
		return frost.Sign(configs[id], signers, message)
	})
	sig, ok := rawSign[signers[0]].(frost.Signature)
	require.True(t, ok, "want frost.Signature, got %T", rawSign[signers[0]])

	encoded, err := sig.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, encoded, 64, "the trap is that it is exactly signature-shaped")

	require.False(t, ed25519.Verify(ed25519.PublicKey(pub), message, encoded),
		"generic FROST output must never be mistaken for an RFC 8032 signature")
}

// TestEd25519StorageRoundTripRejectsForeignShares checks the codec refuses a
// share from another curve rather than silently reinterpreting its bytes. This
// is what makes the "ed25519:" storage prefix a boundary and not just a label.
func TestEd25519StorageRoundTripRejectsForeignShares(t *testing.T) {
	ids := ceremonyParties()

	raw := runCeremony(t, ids, []byte("foreign-share"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenSR25519(id, ids, 1)
	})
	sr, ok := raw[ids[0]].(*frost.Config)
	require.True(t, ok)

	// Written with the sr25519 codec, then offered to the Ed25519 one.
	blob, err := MarshalSR25519Config(sr)
	require.NoError(t, err)

	_, err = UnmarshalEd25519Config(blob)
	require.Error(t, err, "a Ristretto255 share must not load as an Ed25519 share")
}
