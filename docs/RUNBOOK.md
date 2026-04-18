# Lux MPC Operator Runbook

A production checklist for operating a consensus-mode `mpcd` cluster.

This runbook is scoped to operations — the things you run on a Tuesday afternoon. For installation, see [INSTALLATION.md](./INSTALLATION.md); for the health endpoint contract, see [HEALTH.md](./HEALTH.md).

All examples assume a 3-of-5 cluster of consensus-mode nodes (`node0`..`node4`) with the internal API exposed on `:9800`–`:9804` and the dashboard API on `:8081`–`:8085`.

---

## Daily / Periodic Checks

| Cadence | Check | Expected | Signal |
|---------|-------|----------|--------|
| Every 1–5 min (probe) | `GET /healthz` on each node | `200 OK`, `ready: true`, `connected_peers == expected_peers` | K8s liveness/readiness |
| Every 15 min | Drift between node versions | All nodes on same `version` field | Staggered rollout in flight |
| Every hour | Backup success | Newest backup file within `backup_period_seconds` | `/backup` endpoint + S3/GCS log |
| Daily | Audit log review | No unexplained `/keygen` or `/backup` events | Structured logs, `"Audit: ..."` |
| Weekly | Dry-run signature | Smoke test returns 0 | `./scripts/smoke-test.sh` |
| Monthly | Share refresh rehearsal | Reshare in staging completes cleanly | See [Share Refresh](#share-refresh-rotate-shares-public-key-stays) |
| Quarterly | Disaster recovery drill | Restore from backup on cold infra | See [Backup and Restore](#backup-and-restore) |

---

## Health Probes

The only unauthenticated endpoint on the internal API is `/healthz`. Use it for both liveness and readiness:

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 9800 }
  initialDelaySeconds: 15
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  httpGet: { path: /healthz, port: 9800 }
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 2
  failureThreshold: 2
```

Status codes:

- `200 OK` — node is fully joined. `ready: true`, `connected_peers` equals `expected_peers`.
- `503 Service Unavailable` — peers not yet connected or a peer has dropped. `ready: false`, `status: degraded`.

See [HEALTH.md](./HEALTH.md) for the full response schema.

---

## Key Rotation

### Concept

Lux MPC supports two independent rotations:

1. **Share refresh** (a.k.a. "reshare") — rotate every node's share of an existing wallet's key. Public key and address are **unchanged**; all previously-signed transactions remain verifiable. Required on any suspected node compromise, on routine schedule (quarterly recommended), or when adding / removing nodes.
2. **Wallet rotation** — generate a new wallet (new public key, new address) and migrate balances. Used when you want an entirely new key material regardless of share integrity.

### Share Refresh (rotate shares, public key stays)

Triggered via the dashboard API:

```bash
curl -X POST https://mpc.example.com/v1/wallets/<wallet_id>/reshare \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"threshold": 3, "new_peers": ["node0","node1","node2","node3","node4"]}'
```

Preconditions:

- All `new_peers` must be registered in the cluster and healthy (`/healthz` → 200).
- `threshold` must satisfy `t >= floor(n/2) + 1` for the new cohort.
- At least `threshold` of the current peers must be online to produce the reshare signature.

Post-conditions:

- The public key and on-chain address are unchanged.
- Old shares are invalidated; attempting to sign with an old share set fails the protocol.
- The reshare is recorded in audit logs with the new peer manifest hash.

Operator checklist:

- [ ] Confirm all `new_peers` are healthy via `/healthz`.
- [ ] Snapshot the current ZapDB (`/backup`) on every current-cohort node before starting.
- [ ] Schedule the reshare during low-traffic window — signing is paused per-wallet for the duration.
- [ ] After completion, verify `GET /v1/wallets/<wallet_id>` returns the same `public_key` and new `peer_set`.
- [ ] Issue a test signature via `./scripts/smoke-test.sh` against the resharered wallet ID.
- [ ] Destroy pre-reshare backups from all nodes (they contain retired shares — no operational value, incremental blast radius).

### Wallet Rotation (new key)

When a full key replacement is required:

1. Generate a new wallet via `POST /v1/vaults/<vault_id>/wallets`.
2. Move balances on-chain from the old wallet to the new one.
3. Mark the old wallet as retired (`POST /v1/wallets/<id>/retire`).
4. Keep shares of the retired wallet for the configured retention window (default 90 days) in case of dispute.

---

## Node Add / Remove Without Resharing

You cannot change the cohort of an existing wallet without a reshare — the key shares are cohort-specific. But you can grow or shrink the cluster for **new** wallets without touching existing ones:

### Add a node (no reshare required for existing wallets)

1. Provision the node with `mpc generate-identity --node nodeN` using the shared `peers.json`.
2. Distribute the new node's public identity to all existing nodes' identity directories.
3. Restart each existing node with `--peer nodeN@<addr>:9651` added.
4. Start the new node with `--peer` flags pointing at all other nodes.
5. Confirm `/healthz` on every node shows `connected_peers: N` and `ready: true`.
6. New wallets created from this point can use the expanded cohort. Existing wallets still use their original cohort.

### Remove a node (no reshare required for existing wallets)

1. Drain wallets off the node: any wallet whose cohort includes the leaving node must be resharered onto the remaining cohort — or the leaving node stays online until every such wallet has been migrated.
2. Confirm via audit: `GET /v1/wallets?peer=nodeN` returns empty.
3. Stop the node. Remove its `--peer` flag from every remaining node's startup and restart them.
4. Revoke the leaving node's identity from the registered peer set.

---

## Backup and Restore

### Backup

Automatic backups run every `backup_period_seconds` (default 300). Each node writes an age-encrypted archive of its ZapDB to `backup_dir` (default `backups/`). If `S3_BUCKET` / `GCS_BUCKET` env vars are set, the archive is shipped off-host.

Trigger a manual backup:

```bash
curl -X POST http://localhost:9800/backup -H "Authorization: Bearer $INTERNAL_TOKEN"
# {"status":"backup completed"}
```

The `/backup` endpoint is rate-limited; don't automate it against multiple nodes simultaneously — prefer the periodic scheduler.

### Restore

Cold restore of a single node (to replace a failed disk on the same identity):

1. Stop the affected node.
2. Restore the latest backup archive into `<data>/`.
3. Decrypt with age: `age --decrypt -o zapdb.restored <backup_file>.age`.
4. Move decrypted artifacts into `<data>/zapdb/`.
5. Restart the node. It will rejoin the cohort and verify share integrity via `pkg/integrity`.

> **Important.** A backup is a share backup — not a key backup. Restoring a backup on a node with a **different** identity will not give that node usable shares; the share ciphertext is bound to the node's ZapDB password (sourced from HSM) and the original identity.

---

## Incident Triage

### Node shows `ready: false`

1. Check peer count in the `/healthz` response: `connected_peers` < `expected_peers`.
2. For each expected peer, check TCP reachability on the `--listen` port (`nc -z <peer> 9651`).
3. Check peer's own `/healthz`. If the peer is up but not reachable, this is a network issue — firewalls, service mesh, NetworkPolicy.
4. Tail logs for `transport: peer <id> disconnected` or `transport: dial failed` and remediate the underlying network.
5. Node does **not** need a restart just to re-join — the transport reconnects when peers become reachable. If it doesn't, restart with `--log-level=debug` and capture the handshake.

### Signing timeouts (`keygen timed out after 60s`)

1. Check the event initiator pubkey matches on every node (`grep event_initiator_pubkey` across `config.yaml`).
2. Verify `/healthz` on every node — if any node in the wallet's cohort is degraded, threshold may not be reachable.
3. Check `MAX_CONCURRENT_KEYGEN` — parallel keygen requests are queued, not rejected. If you see sustained backlog, increase `max_concurrent_keygen` and restart.
4. Look for `Audit: keygen triggered` without a matching result event in pubsub — indicates the keygen is stuck in the protocol layer, likely a peer missed a round.

### Suspected node compromise

1. Immediately isolate the node: `kubectl delete pod mpc-node-<N>` or firewall it off.
2. Reshare all wallets whose cohort includes the compromised node, onto a cohort that **excludes** it. See [Share Refresh](#share-refresh-rotate-shares-public-key-stays).
3. Rotate the ZapDB password (HSM side) and re-encrypt archived backups at rest.
4. Destroy backups that contain shares held by the compromised node.
5. File incident report; include log excerpts, relevant wallet IDs (never their private material), and timeline.

### HSM / KMS outage

- Existing running nodes cache the ZapDB password in memory and continue operating until restart.
- New nodes and restarts cannot proceed — they will fatal with `resolve ZapDB password: ...`.
- If the outage is long-running, do **not** failover to an `env` or `file` password provider in production — the startup guard rejects it, and doing so defeats the HSM boundary. Wait for KMS, or stand up nodes in the secondary region with a mirrored KMS key.

---

## Rollback

A `mpcd` release is rolled back by:

1. Redeploying the previous container image tag. The on-disk ZapDB is forward-compatible within a major version; rolling back a minor/patch has not broken shares across the 0.1.x / 0.2.x / 0.3.x lineage.
2. If a schema migration was applied, restore from the pre-migration backup on every node (see [Restore](#restore)).
3. Confirm `/healthz` everywhere before re-admitting traffic.

Never roll back **only some** nodes — mixed-version cohorts are not a supported configuration for signing.

---

## Logs and Audit

- Structured JSON logs to stdout. Fields of operational interest: `nodeID`, `walletID`, `orgID`, `remote`, `keygenID`, `resharedFrom`.
- Audit events start with `"Audit:"` — keygen trigger, backup trigger, reshare trigger. These are the authoritative record of sensitive operations and should be shipped off-host with tamper-evident retention.
- Protocol-layer failures are logged at `warn`/`error` with the session ID; correlate across all cohort nodes when triaging.

---

## Useful One-Liners

```bash
# Cluster-wide health
for n in 0 1 2 3 4; do echo -n "node$n: "; curl -sf http://localhost:980$n/healthz | jq -r '.status + " peers=" + (.connected_peers|tostring) + "/" + (.expected_peers|tostring)'; done

# Trigger a backup on every node
for n in 0 1 2 3 4; do curl -sf -X POST -H "Authorization: Bearer $TOKEN" http://localhost:980$n/backup; done

# Count keys across the cluster (should be identical per node)
for n in 0 1 2 3 4; do echo "node$n: $(curl -sf -H "Authorization: Bearer $TOKEN" http://localhost:980$n/keys | jq 'length')"; done

# Tail audit trail
stern mpc-node | grep -E '"Audit:|ERROR'
```
