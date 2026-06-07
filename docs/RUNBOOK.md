# MPC Operator Runbook (Outline)

Day-to-day operator reference for a `mpcd` consensus-mode cluster.

This document is intentionally an **outline**. Each section lists the
shape of the procedure and the commands an operator runs; protocol-level
detail (exact reshare sequence, slashing semantics, recovery state
machine) is owned by the maintainers and is marked `TODO(maintainer)`
where it has not been filled in yet. PRs welcome.

> **Scope.** Consensus-mode (`mpcd`) only. Legacy `lux-mpc` clusters are
> covered in `INSTALLATION.md` Appendix A and are not in scope here.

---

## 0. Cluster topology at a glance

- `n` nodes (StatefulSet pods / VMs), each running `mpcd start ...`
- Quorum: `ready_count >= threshold + 1` for signing; **all** peers must
  be ready for keygen of fresh wallets
- Default ports per node:
  - `9999` — P2P ZAP transport (peer ↔ peer)
  - `9800` — internal MPC API (bearer-auth, K8s-internal only)
  - `8081` — dashboard API (JWT-auth, may be ingressed)
  - `9653` — KMS-facing ZAP (consumed by `luxfi/kms`)
  - `7301` — embedded threshold dispatcher (loopback by default)
- Persistent state: `--data` directory (key shares in ZapDB, dashboard
  in SQLite, backups under `backups/`)

---

## 1. Bring-up checklist

Run through this when standing up a new cluster or after a planned full
restart.

- [ ] All node identities (`<data>/keys/<node-id>_identity.json`) backed
      up off-host before first start.
- [ ] HSM password provider reachable (`aws kms decrypt` or equivalent
      smoke test from the host network).
- [ ] `MPC_INTERNAL_API_KEY` set on every node and identical across the
      cluster.
- [ ] `JWT_SECRET` set for the dashboard API.
- [ ] `mpcd start` succeeds on each node — logs show
      `[READY] Node is ready (consensus mode)`.
- [ ] `/healthz` returns `signing_quorum: true` on every node.
- [ ] Smoke test passes (see §8).

---

## 2. Health endpoints and probes

`mpcd` exposes two health surfaces. Both are unauthenticated so that
Kubernetes probes work without secret injection.

- `GET /healthz` (port 9800) — node-level. Returns:
  - `200 status=healthy` — signing quorum holds and every peer is ready
  - `200 status=healthy-reduced` — signing quorum holds, ≥1 non-critical
    peer unreachable
  - `503 status=degraded` — signing quorum lost
- `GET /health` (legacy alias of `/healthz`).

Recommended Kubernetes probes:

- **Liveness:** `/healthz`, period `30s`, failure threshold `5`. Restart
  only on prolonged failure — transient quorum gaps are recoverable.
- **Readiness:** `/healthz`, period `10s`, failure threshold `2`. A 503
  removes the pod from the dashboard service endpoints.

`TODO(maintainer)`: confirm whether a dedicated readiness path is
preferred over reusing `/healthz` for very large (n>7) clusters.

---

## 3. Key rotation (reshare)

The reshare flow rotates per-share material **without** changing the
wallet's public key. Use it on a regular cadence and on personnel
change.

- [ ] Stage the new participant set and threshold.
- [ ] Confirm the cluster is at full quorum (`/healthz` healthy on every
      node) before starting — reshare requires all current participants.
- [ ] Trigger reshare via the dashboard API or by publishing to the
      `mpc:reshare` topic (`ConsensusMPCBackend.TriggerReshare` in
      `cmd/mpcd/main.go`).
- [ ] Verify the new key info on every node (`GET /keys` on port 9800).
- [ ] Retire old share material from the previous participant set once
      every node has acknowledged the new shares.

`TODO(maintainer)`: document the exact wire shape of the reshare event
(org_id, wallet_id, new_threshold, new_participants[]) and the expected
result topic.

---

## 4. Backup and restore

`mpcd` runs a periodic ZapDB backup driven by `backup_period_seconds`
(default 300 s). Backups land in `<data>/backups/` and, when the
`MPC_BACKUP_S3_*` env vars are set, are uploaded to S3 by
`pkg/backup.Manager`.

### Backup

- [ ] Verify the periodic backup is running (`grep "Periodic ZapDB
      backup completed" mpcd.log` on each node).
- [ ] On demand: `curl -X POST -H "Authorization: Bearer
      ${MPC_INTERNAL_API_KEY}" http://<node>:9800/backup`.

### Restore (single node)

- [ ] Stop `mpcd` on the affected node.
- [ ] Restore the latest `<data>/backups/<node-id>.zapdb.bak` file into
      `<data>/db/<node-id>/`.
- [ ] Restore `<data>/keys/<node-id>_identity.json` from off-host backup
      (the identity is **not** in the ZapDB backup).
- [ ] Restart `mpcd`. The node rejoins, repopulates the peer registry,
      and `/healthz` flips back to `healthy`.

`TODO(maintainer)`: describe the restore-from-S3 flow and the
verification step that a restored share is byte-identical to peers'
view of the same wallet.

---

## 5. Add / remove a node without resharing

This procedure changes cluster size **without** rotating shares. It is
appropriate for scaling capacity, not for rotating key material — for
that, use §3 (reshare).

### Add

- [ ] Provision the new pod / VM with a clean `--data` volume.
- [ ] Generate the new node's identity (first start creates it under
      `<data>/keys/`).
- [ ] Update the `--peer` flags on every existing node to include the
      new address.
- [ ] Rolling-restart the existing nodes. Quorum is preserved as long as
      `ready_count >= threshold + 1` throughout the rollout.
- [ ] The new node will not hold shares for existing wallets until a
      reshare is triggered — see §3.

### Remove

- [ ] Confirm the cluster can tolerate `n - 1` (i.e. `n - 1 >= threshold
      + 1`).
- [ ] Drain and stop the node.
- [ ] Remove the node's address from `--peer` on remaining nodes;
      rolling-restart.
- [ ] `TODO(maintainer)`: confirm whether the removed node's share
      material should be cryptographically retired (re-shared away) or
      whether physical destruction is sufficient given the share is
      single-party-useless.

---

## 6. Recovery from share loss

If a single node loses its `--data` volume but the cluster still has
`t-of-n` quorum.

- [ ] Confirm `n - 1 >= threshold` — the cluster can still sign.
- [ ] `TODO(maintainer)`: document whether `pkg/mpc/recovery.go`
      exposes an operator-facing restore-from-quorum flow, or whether
      the only path is reshare into a fresh share for the affected
      node.
- [ ] After recovery, run the smoke test (§8) before returning the node
      to production traffic.

If the cluster has lost **more than `n - t`** nodes (below signing
quorum), restore from off-host backups (§4) is the only option.

---

## 7. Slashing / misbehaviour response

`TODO(maintainer)`: the cluster currently treats peer misbehaviour as a
liveness signal (`ArePeersReady` flips false, `/healthz` may downgrade).
Operator response should cover:

- [ ] Identifying the offending peer from `mpcd` logs (signature
      verification failure, repeated wire-protocol violations).
- [ ] Quarantining the peer (remove from `--peer` set, rolling-restart).
- [ ] Forensic capture of the peer's `<data>/` and recent log window.
- [ ] Re-keying via reshare (§3) once root cause is established.

Document the threshold above which misbehaviour requires share rotation
vs. simple peer removal.

---

## 8. Deployment-validation smoke test

Run after every cluster start, every K8s rolling update, and as a
post-deploy gate in CI.

- [ ] `for n in node0 node1 node2; do curl -fs http://${n}:9800/healthz
      | jq -e '.signing_quorum == true'; done`
- [ ] Keygen a throwaway wallet via the dashboard API or `/keygen` on
      port 9800.
- [ ] Sign a fixed nonce against that wallet.
- [ ] Verify the signature off-cluster (e.g. `secp256k1`/`ed25519`
      verify with the returned public key).
- [ ] Tear down the throwaway wallet.

`TODO(maintainer)`: a packaged `scripts/smoke-test.sh` that wraps the
above into a single exit-coded command would be a useful follow-up;
issue #1 proposed it explicitly.

---

## 9. Log locations and verbosity

| Location | Contents |
|----------|----------|
| stderr (default) | Structured logs from `pkg/logger`. Capture via the systemd journal or the K8s pod log stream. |
| `<data>/backups/` | Periodic ZapDB backups. Not log data — but useful in incident timelines. |
| `<data>/dashboard.db` | Dashboard SQLite (audit/admin trail). |

Increase verbosity with `--log-level debug` or `--debug`. **Do not** run
production with debug logging — wire messages and identities are not
logged, but timing data leaks downstream operator information.

Key audit log lines to grep for:

- `Audit: keygen triggered` — every `/keygen` invocation
- `Audit: backup triggered` — every manual backup
- `[READY] Node is ready` — successful start
- `Periodic ZapDB backup completed successfully` — backup heartbeat
- `Shutdown signal received` — graceful stop
