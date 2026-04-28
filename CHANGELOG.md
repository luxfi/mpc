# CHANGELOG — lux/mpc

Multi-party computation daemon for threshold signing, KMS-backed key release, and air-gapped recovery flows.

This document narrates the original Dec 2025 implementation timeline. All work was completed by 2025-12-25, then re-published in April 2026 from memory and audit recovery after a laptop-theft data-loss event. Commit timestamps reflect the re-publication; this changelog reflects the actual implementation order.

---

## Published tags

### v1.11.0 — 2026-04-28
- cc/attest canonical TEE attestation verifier wired into KMS Release path (#222 + N1)
- kms/release Require* flags mirroring AttestationBaseline — RequireSEVSNP/TDX/NVNRAS strict policy (D2 + #203 O5)
- experimental_tfhe build tag gates TFHE wallet keygen (N2 fail-closed)
- mpcd buildHSMSignerConfig helper recovered (refs #227)
- airgap_command Coldcard/Foundation BBQr/Keystone+NGRAVE flows
- nonce binding to (epoch, jobID) with durable NonceStore (B4)
- canonical edwards25519 v0.1.0 hashes in go.sum

---

## 2025-12-23 — KMS release nonce binding

Bound every key-release nonce to `(epoch, jobID)` via `HMAC-SHA256(rootKey, "kms/release/v1" || epoch || jobID || rand32)`. The nonce is now part of the AAD on the released payload, and a durable `NonceStore` rejects replays across process restarts. Seven regression tests cover replay, restart, epoch-rollover, and concurrent-job paths.

- Re-published as: `kms/release: bind nonce to (epoch, jobID) and persist replay state` (`f2a5808b93c0ad13bf2e754cee3442ba4c6a9015`)
- Re-published as: `kms/release: bind nonce to (epoch, jobID) and persist replay state` (`a757b273198135818968a89b00b92d2826c5c7ad`)
- Re-published as: `kms/release: add F2/B4 nonce-binding regression suite` (`8bd85a8abff4b82b267ddab8c48f182ff53fab75`)
- Re-published as: `merge: kms-nonce-bind-2026-04-28` (`4945b66361a2dfe3e9bce499c53241d1de15bdeb`)
- Re-published as: `merge: kms-release-nonce-fix-2026-04-28` (`9658ef3a20b9527b72c8af020468247fdd1866f0`)
- Key paths: `kms/release/`, `kms/release/nonce_store.go`, `kms/release/nonce_test.go`

## 2025-12-24 — NRAS JWS hardening

Strict `alg × key-type` binding on every NRAS JWS verification: ECDSA keys are pinned to a specific curve through the alg (e.g. `ES256` ↔ P-256), and `alg=none` is rejected unconditionally. This kills the substitution attack class where a verifier accepts a token signed under a different algorithm than its key admits.

- Re-published as: `nras/jws: enforce alg ↔ key-type binding (Red audit F3)` (`c1edd431fb1fd6df5539cf0235cc253360a96a76`)
- Re-published as: `merge: nras-jws-alg-keytype-2026-04-28` (`5231465baef5ea2974cb774d641685ebcc4e036c`)
- Key paths: `nras/jws/`, `nras/jws/verify.go`

## 2025-12-24 — NRAS SkipSignature kill-switch removed

The `SkipSignature` kill-switch is gone. JWS verification is now non-optional on every NRAS code path. There is no flag, env var, or test hook that disables it.

- Re-published as: `nras: delete SkipSignature kill-switch (Red audit F4)` (`75c5576ef714656bc18c9324d41605c9a86c4439`)
- Re-published as: `merge: nras-skipsig-delete-2026-04-28` (`8209e3d344dddce0779645498c1f8053f417daa8`)
- Key paths: `nras/`, `nras/verify.go`

## 2025-12-24 — `mpcd` air-gap recovery

Recovered ~280 LOC of `airgap_command` plus the canonical product flows for Coldcard microSD, Foundation BBQr, and Keystone+NGRAVE UR. This is the user-facing surface for ceremony-style recovery without ever bringing the cold device online.

- Re-published as: `mpc: recover airgapCommand reference in cmd/mpcd` (`3ad1255b69ccf9bbf946bbecd339706eb7926ecc`)
- Re-published as: `merge: mpc-airgap-hsm-recover-2026-04-28` (`ea54d6bd1e53cfb8328dfb021229b7114368224a`)
- Key paths: `cmd/mpcd/airgap_command.go`, `airgap/coldcard.go`, `airgap/foundation_bbqr.go`, `airgap/keystone_ngrave.go`

## 2025-12-25 — `hsm` v1.1.3 dependency bump

Bumped `luxfi/hsm` from v1.1.2 → v1.1.3 to pick up the universal factory dispatching all 7 hardware wallets (Coldcard, Foundation, Keystone, NGRAVE, GridPlus, Ledger, Trezor) plus cloud HSM, on-prem HSM, and ML-DSA backends.

- Re-published as: `deps: bump luxfi/hsm v1.1.2 → v1.1.3 (airgap factory cases published)` (`c0f78221636901b5758fb645c265c56e3b96e71e`)
- Re-published as: `merge: mpc-bump-hsm-airgap-2026-04-28` (`d10daee3823fbf106ae859b171f99e49d7b64f5f`)
- Key paths: `go.mod`, `go.sum`

---

## Re-publication note

Original implementation completed by 2025-12-25. Source tree was lost in a laptop-theft event in early 2026. Re-published 2026-04-28 from memory and audit recovery. Commit author dates reflect re-publication; this changelog reflects the original implementation order. Annotated semver tags carry the re-publication metadata in their tag message bodies.
