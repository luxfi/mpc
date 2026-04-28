# mpcd — MPC Daemon

`mpcd` is a threshold-signature daemon. It speaks ZAP wire protocol over
TLS 1.3 directly between peers — no NATS, no Consul, no PostgreSQL in the
critical path. The daemon is the same binary in every deployment shape;
the operating mode is selected entirely by flags.

## Operating modes

There is exactly one start command (`mpcd start`) and the topology is
determined by the `--peer` and `--threshold` flags:

| Topology | Flags | Use |
|----------|-------|-----|
| Standalone (1-of-1 self-loop) | `--threshold 1` (no `--peer`) | Smoke tests, dev sandbox |
| Networked t-of-n cluster | `--threshold t --peer ...` (n−1 peers) | Production |

In all cases mpcd runs the consensus-embedded transport
(`pkg/transport`). The "consensus" here is local PoA membership over the
node's own Ed25519 identities — it is intentionally not the Lux mainnet
chain, because key shares must never leave the cluster.

## Standalone (1-of-1)

```sh
mpcd start \
    --node-id solo \
    --listen :9999 \
    --api :9800 \
    --data /var/lib/mpcd \
    --threshold 1
```

Starts mpcd with itself as the only quorum member. `/healthz` will report
`signing_quorum: true` immediately. **Keygen and signing of fresh wallets
require ≥2 parties** — CGGMP21 and FROST cannot produce shares with a
single party — so this mode exists only for boot-up smoke tests, e2e
harness fixtures, and verifying TLS / membership / API plumbing. For real
signing, run a multi-node cluster.

## Networked (t-of-n)

```sh
# Node 0
mpcd start --node-id node0 --listen :9999 --api :9800 \
    --data /data/node0 --threshold 2 \
    --peer node1@10.0.0.2:9999 --peer node2@10.0.0.3:9999

# Node 1
mpcd start --node-id node1 --listen :9999 --api :9800 \
    --data /data/node1 --threshold 2 \
    --peer node0@10.0.0.1:9999 --peer node2@10.0.0.3:9999

# Node 2 — same pattern
```

The daemon expects the cluster size n = len(peers) + 1 and rejects start
when threshold > n. See `pkg/transport/registry.go::HasSigningQuorum` for
the quorum arithmetic.

## Smoke test

```sh
go test -tags=integration ./cmd/mpcd/... -count=1 -timeout 90s
```

`standalone_test.go` builds mpcd, runs it with `--threshold 1` on free
ports and a fresh data directory, polls `/healthz` until quorum holds,
and asserts the response shape. It does not exercise keygen — see `e2e/`
for that.
