# Migration from Fireblocks to lux/mpc

This is the operational runbook for moving a fund / institution off
Fireblocks onto the lux/mpc stack. It is the only document on this
subject — there are no aliases, no shorter version, no deprecated
predecessors.

Audience: head of treasury, head of compliance, head of engineering.
Read it once end-to-end before kicking off the migration.

## TL;DR (one screen)

You cannot copy keys out of Fireblocks. Their MPC-CMP shares are
non-extractable by design — that is the same property that makes them
secure. So the migration is **not** a key transfer. It is:

1. Spin up lux/mpc nodes, run a fresh DKG ceremony for every wallet.
2. Move assets from old Fireblocks address → new lux/mpc address with a
   real on-chain transfer.
3. Migrate the policy graph (TAP rules, signers, allowlists) by export
   from the Fireblocks Console + import into lux/mpc.
4. Cut over webhook + API integrations.
5. Decommission the old workspace.

Total wall-clock for $1B+ AUM: **4-6 weeks**, parallelizable across asset
classes. The bottleneck is not technology. It is signoff: every wallet
move requires the same N-eyes approval that ordinary transfers do, and
your auditor wants the trail.

## Pre-flight checklist

| # | Item | Owner | Done when |
|---|---|---|---|
| 1 | Stand up lux/mpc cluster (3+ nodes, separate cloud accounts) | platform | `kubectl get pods -n lux-mpc` shows 3 ready |
| 2 | Mint a KMS project per legal entity | platform | KMSSecret CRDs sync into the cluster |
| 3 | Provision Hanzo IAM org + invite signers | compliance | Each signer has logged in once and has WebAuthn registered |
| 4 | Spin up lux/mpc UI on `mpc.<your-domain>` | platform | TLS cert valid, login works |
| 5 | Configure Chainalysis KYT + (optional) TRM Labs | compliance | Test address screen returns Verdict |
| 6 | Configure SecureGate (or alternative liveness provider) Ed25519 pubkey | platform | `MPC_SECUREGATE_PUBKEY_ED25519` set, biometric enroll returns 200 |
| 7 | Audit log dispatcher → choose mode: WORM file, M-Chain anchor, or composite | compliance | First audit event lands at the destination |
| 8 | Webhook receivers — every Fireblocks consumer rewires to the new endpoint | engineering | `/v1/webhooks/{id}/test` succeeds end-to-end |
| 9 | Backup procedure — wallet shares to S3 + KMS-wrapped Glacier | platform | `lux-mpc-cli recover` round-trip on a test wallet |

When all 9 are green, you are ready to migrate the first wallet.

## Phase 1 — Inventory (week 0)

Pull the Fireblocks workspace export. From the Fireblocks Console:

- Vault accounts list (CSV)
- Per-vault asset balances (CSV)
- TAP rules (the rule editor → export-as-JSON)
- Whitelisted destinations (CSV)
- API users + roles + permissions
- Webhook configurations

Stage these in a private repository under `audit/<your-org>/<date>/`.
Compliance signs off on the snapshot before anyone moves a satoshi.

Map every Fireblocks vault → exactly one lux/mpc tier:

| Fireblocks pattern | lux/mpc tier | Reason |
|---|---|---|
| Operating wallet, daily withdrawals | `hot` | Low value cap, allowlist, auto-approve |
| Treasury reserves, multi-week TTL | `cold` | 3-of-5, 24h timelock, airgap |
| Bridge custody | `bridge` | Per-route allowlist, KYT |
| Validator stake | `validator` | Spend ban, slash-proof |
| Quarantined / compliance hold | `quarantine` | 0 spend until human release |
| Disaster recovery shadow | `disaster_recovery` | 7-day timelock, airgap |

Document the mapping in `audit/<your-org>/<date>/tier-mapping.md`. This
is the input to Phase 2.

## Phase 2 — Wallet creation (week 1-2)

For every Fireblocks vault in your inventory:

1. Pick the destination tier from the mapping table.
2. Provision the lux/mpc node binding for that tier — distinct cloud
   accounts, distinct HSM vendors per the tier's domain-separation
   requirement (`pkg/wallet/registry.go` enforces this at create time).
3. Run DKG: `POST /v1/wallet/` with the tier and the threshold.
4. Persist the new address to your inventory record. **Do not move funds
   yet.**

Throughput estimate: one DKG per node-set per ~30 seconds. A workspace
with 200 vaults: ~2 hours of cluster time, plus ops review per wallet.
Run the ceremony in a single morning, sign each wallet off in batches.

Validation checks (every new wallet, before funds move):

- [ ] `GET /v1/mpc/wallets/{id}` returns the wallet with the expected
      tier
- [ ] `POST /v1/mpc/sign` with a dummy 32-byte digest produces a
      verifiable signature (regression for keygen success)
- [ ] Every signer can WebAuthn-approve a test policy event
- [ ] Audit log shows the keygen event chained to its predecessor

## Phase 3 — Policy migration (week 2)

TAP rules in Fireblocks map to two surfaces in lux/mpc:

- `/v1/mpc/policies` — the dynamic per-org rules (Conditions + Actions
  + ApproverConfig)
- The static per-tier policy in `pkg/wallet/tier.go`

Walk every Fireblocks rule:

| Fireblocks field | lux/mpc target |
|---|---|
| Source = vault account | Filter on `walletId=` (or `tier=`) at create time |
| Asset filter | `Condition{Type: ConditionAsset, Operator: OpEquals, Value: "USDC"}` |
| Amount threshold | `Condition{Type: ConditionAmount, Operator: OpGreaterThan, Value: "..."}` |
| Destination = whitelist | `Condition{Type: ConditionWhitelist}` plus populated `AddressWhitelist` rows |
| "Require N approvals" | `Action: ActionRequireApproval`, `Signers.RequiredCount: N` |
| "Block" | `Action: ActionDeny` |
| Time-of-day window | `TimeWindow{StartHour, EndHour, AllowedDays, Timezone}` |
| Velocity limit | The tier policy's `VelocityWindow` + `VelocityLimitWei`, or a custom `RateLimit` on the rule |

Compliance signs off on the migrated rule set before any production
wallet receives traffic.

## Phase 4 — Asset transfers (week 2-4)

This is the expensive part. Every Fireblocks address you keep funds in
needs an explicit on-chain (or off-chain settlement) transfer to its
new lux/mpc counterpart.

Sequence per wallet:

1. **Freeze the Fireblocks side**: tighten its TAP to "deny all
   outbound except to <new lux/mpc address>". This prevents accidental
   outflows during the move.
2. **Schedule the move** in the lux/mpc operations queue. Initiate
   from the receiving wallet (use `/v1/mpc/wallets/sweep` if the source
   has multiple UTXOs/balances; otherwise a single send).
3. **N-eyes approval** on the Fireblocks side (your existing TAP) +
   **N-eyes confirmation** on the lux/mpc side that the receiving
   address is correct. Both teams sign separately.
4. **Verify on-chain**: receiving wallet sees the funds, expected
   confirmations cleared.
5. **Decommission**: lock the Fireblocks vault to "cannot send" and
   schedule deletion at the end of the migration.

Per-asset notes:

- **Bitcoin**: dust-consolidate before the move. Target one or two
  outputs to the new address. Use the lux/mpc `pkg/automation/feebump.go`
  RBF helper if a transfer gets stuck in the mempool.
- **EVM (ETH/USDC/etc)**: gas the source wallet with a dust top-up if
  it's empty (Fireblocks sometimes leaves vaults with 0 ETH). Use the
  EIP-1559 fee path for predictable inclusion.
- **Solana / TON / cross-chain**: each has its own quirks; the runbook
  per chain lives in `~/work/lux/mpc/docs/chains/<chain>.md` (or your
  ops wiki). The protocol path is the same — `POST /v1/mpc/sign` —
  but the tx-build differs per chain.

For very large balances (>$100M per move), break the move into tranches
spread over 24–72 hours. This bounds the loss surface if anything goes
sideways and gives the auditor a clean transactional trail.

## Phase 5 — Integration cutover (week 3-4)

API consumers that talk to Fireblocks today:

| Consumer | Fireblocks endpoint | lux/mpc endpoint | Notes |
|---|---|---|---|
| Trading desk (order signing) | `POST /v1/transactions` | `POST /v1/mpc/sign` or `POST /v1/mpc/settlement/sign` | Rate-limited 20 RPM/IP |
| Webhook consumer (tx state) | Fireblocks webhook | `/v1/webhooks` config + your receiver | HMAC signing key per-webhook |
| Address book sync | `/whitelisted_addresses` | `/v1/whitelist` | Same shape, different surface |
| Audit pull | Fireblocks audit log API | `/v1/mpc/audit` | Cryptographically chained — verify with `audit.VerifyChain` |
| Mobile approval | Fireblocks mobile app | lux/mpc UI biometric flow on `mpc.<your-domain>` | Push notification config required |

Run the old and new in parallel for at least one full reporting cycle
(typically one calendar month) so quarterly reports cross-validate.

## Phase 6 — Compliance handover (week 4-6)

| Artifact | Source | Destination |
|---|---|---|
| SOC 2 Type II report | Fireblocks (vendor SOC) | Your auditor; replaced by lux/mpc's own SOC 2 once issued |
| Custody insurance | Fireblocks-arranged Marsh/Aon policy | Your broker — re-underwrite with lux/mpc as custodian |
| Travel rule attestations | Fireblocks built-in | Out-of-band integration; document the new flow |
| Sanctions screening | Fireblocks Chainalysis | lux/mpc Chainalysis (`pkg/risk/chainalysis.go`) — same vendor, you bring your own API key |
| Audit log evidence | Fireblocks API export | lux/mpc audit log + M-Chain anchor proof |

Two artifacts are genuinely irreplaceable in the short term:

- **Insurance** — you must re-underwrite. The carriers underwriting
  Fireblocks today are the same carriers we engage; the policy
  documents differ but the substantive coverage is comparable. Plan
  a 4-6 week broker cycle.
- **SOC 2 history** — your old controls evidence still belongs to your
  org. The new control surface is documented in lux/mpc's own audit
  trail; carry forward both until the next attestation cycle.

## Phase 7 — Decommission (week 5-6)

When every vault has been emptied + verified:

1. Submit a workspace-deletion request to Fireblocks. They retain
   internal records per their data-retention policy; that is fine.
2. Rotate every API key your systems still hold for the old workspace.
3. Archive the export from Phase 1 to immutable storage (S3 Object
   Lock / Azure Immutable Blob / GCS Object Lock). 7-year retention
   minimum for financial-services contexts.
4. Internal post-mortem: what broke, what was over-budget, what would
   you do differently. Feed back into this runbook.

## Risk register

| Risk | Mitigation |
|---|---|
| Wrong destination address on a move | Two independent humans verify the address against the wallet's `pkg/wallet/registry.go` record before approval. The receiving wallet also must already have a recent successful no-op signature in its history. |
| Stuck Bitcoin transfer | `pkg/automation/feebump.go` RBF helper — every BTC tx is RBF-flagged at build time |
| EVM nonce gap or stuck tx | `pkg/automation/feebump.go` EIP-1559 fee bump using the existing nonce |
| Compromised signer during migration | All signers WebAuthn-bound to their actual hardware; biometric enrollment LAX/STRICT toggle (`MPC_LIVENESS_BINDING`) — keep STRICT during migration |
| Webhook downtime → ops blind | Run old + new in parallel for one reporting cycle; don't decommission Fireblocks webhooks until lux/mpc webhook delivery has logged a clean cycle |
| Auditor pushback on chain-of-custody | Audit log Merkle-chain + M-Chain anchor (`pkg/audit/mchain.go`) is replayable end-to-end |

## Timeline summary

| Week | Phase | Owner | Exit criterion |
|---|---|---|---|
| 0 | Pre-flight + Phase 1 inventory | platform + compliance | tier-mapping.md merged |
| 1 | Phase 2 wallet creation (batch 1: low-value) | platform | First batch DKG + verification done |
| 2 | Phase 2 wallet creation (batch 2: high-value cold) + Phase 3 policy migration | platform + compliance | All wallets exist, all rules ported |
| 3 | Phase 4 asset transfers (high-frequency wallets first) + Phase 5 integration cutover | platform + treasury + engineering | Trading desk live on lux/mpc |
| 4 | Phase 4 asset transfers (cold + treasury) | treasury | All funds on lux/mpc, parallel-run mode |
| 5 | Phase 6 compliance handover | compliance | Insurance + audit signed off |
| 6 | Phase 7 decommission | platform | Old workspace deleted, evidence archived |

For workspaces under ~$200M AUM, weeks 3 and 4 collapse into one. For
workspaces over ~$5B AUM, plan for 8 weeks instead of 6 — not because
the technology takes longer, but because your auditor will want longer
between batches.

## What you keep, what you lose

You keep:
- Every dollar of value (no haircut, no spread)
- Every TAP rule, every approver, every allowlist entry
- Chainalysis screening (same vendor, your API key)
- WebAuthn / mobile approval (with new device enrollments)

You lose:
- Fireblocks-arranged insurance policy (re-underwrite via your broker)
- Fireblocks "Reactor" forensic UI (use Chainalysis Reactor directly,
  or our policy-engine query surface)
- MPC-CMP-specific quirks (we use CGGMP21 — same family, public spec)

You gain:
- Open-source codebase you can read, fork, and audit
- Air-gapped signing as a first-class flow (`pkg/airgap/`)
- 9-tier wallet model with cryptographic domain separation
- Per-node policy verification (no quorum-bypass risk)
- Post-quantum approval providers (`pkg/approval/provider_mldsa.go`)
- Treasury 3-of-5 with regulator shard built in
- M-Chain audit anchoring

## Support

- Architecture questions: cto@hanzo.ai
- Operational runbook: ops@hanzo.ai
- Compliance / audit: compliance@hanzo.ai

This document is the single source of truth for the migration. If
something contradicts it, this document wins; submit a PR to update it.
