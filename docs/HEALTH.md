# Lux MPC Health Endpoint Specification

The `mpcd` node exposes a single unauthenticated health endpoint on the internal API listener (`--api`, default `:9800`). All other endpoints on this listener require an internal-auth bearer token.

## Endpoints

| Path | Method | Auth | Purpose |
|------|--------|------|---------|
| `/healthz` | `GET` | none | Liveness + readiness probe, cluster status summary |

> Historical note: `/health` (without the `z`) was the pre-0.3 path. `/healthz` is the platform-standard alias. New probes should use `/healthz`.

## Response Schema

The endpoint returns a JSON body regardless of HTTP status code.

```json
{
  "status":          "healthy | degraded",
  "node_id":         "node0",
  "mode":            "consensus",
  "expected_peers":  2,
  "connected_peers": 2,
  "ready":           true,
  "threshold":       2,
  "version":         "0.3.3"
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `status` | string | `"healthy"` when the node is fully joined; `"degraded"` when any expected peer is missing. |
| `node_id` | string | The `--node-id` this process was started with. |
| `mode` | string | Transport mode — `"consensus"` for ZAP-based, `"legacy"` for NATS+Consul. |
| `expected_peers` | int | Number of peers configured via `--peer` flags (does not include self). |
| `connected_peers` | int | Number of peers for which the transport currently reports an active connection. |
| `ready` | bool | `true` iff `connected_peers == expected_peers` AND the peer registry has completed initial handshake. |
| `threshold` | int | Signing threshold the node was started with (`--threshold`). |
| `version` | string | `mpcd` binary version (matches `mpcd version`). |

## HTTP Status Codes

| Code | Condition |
|------|-----------|
| `200 OK` | `ready: true`. All expected peers connected. |
| `503 Service Unavailable` | `ready: false`. Peers not yet handshaked or one or more peers dropped. |

No 4xx codes are returned — the endpoint has no inputs other than path + method.

## Probe Recommendations (Kubernetes)

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9800
  initialDelaySeconds: 15
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /healthz
    port: 9800
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 2
  failureThreshold: 2
```

Rationale:

- **Liveness** fires only after 3 consecutive failures over ~30 s. Transient peer reconnects should not restart the pod.
- **Readiness** is tighter (2 consecutive failures, ~10 s). A pod that loses peers should be removed from service rotation quickly — signing traffic on a degraded node will time out.
- `initialDelaySeconds` accounts for consensus-mode peer discovery — nodes may take ~5–10 s after start before `connected_peers` stabilizes, depending on network warmup.

For a load balancer in front of the dashboard API (`--api-listen`, default `:8081`), use the same endpoint on the internal port — the dashboard API itself does not expose a distinct healthz.

## Sampling Cadence

| Consumer | Interval | Rationale |
|----------|----------|-----------|
| K8s livenessProbe | 10 s | Default; accommodates brief transport hiccups. |
| K8s readinessProbe | 5 s | Fast failover out of service rotation. |
| External monitoring (Prom blackbox, Datadog HTTP check) | 15–30 s | Status dashboards, alerting. |
| Incident triage | on-demand | Manual `curl`. |

Do not poll faster than every 1 s from external sources — the endpoint is cheap (no DB or protocol I/O) but aggregating several pollers hitting at higher rates adds log noise without added signal.

## Alerting

Recommended alert rules (Prometheus-style, adapt to your stack):

```promql
# Any node degraded for > 2 minutes
sum by (node_id) (
  probe_success{job="mpc-healthz"} == 0
) > 0 for 2m

# Cluster-wide loss of readiness — fewer than threshold nodes healthy
count(probe_success{job="mpc-healthz"} == 1) < 3

# Version drift (staggered rollout that stalled)
count(count by (version) (mpc_version_info)) > 1 for 30m
```

## What `/healthz` Does NOT Check

The endpoint is intentionally narrow. It does **not** verify:

- That the ZapDB is unsealable with the HSM-resolved password (happens once at startup).
- That `event_initiator_pubkey` is valid.
- That recent signing operations have succeeded.
- That the peer registry matches the `peers.json` manifest — only that the expected count of peers are currently connected.

For deeper verification (keygen + sign round-trip), use `scripts/smoke-test.sh` as a periodic canary, not the health probe.
