// Package automation implements the operational automations that close the
// last gap between Fireblocks-class custody and lux/mpc:
//
//   - GasStation — keep operational ("hot") wallets topped up so signing
//     never blocks on fee insufficiency. Source-of-funds is a configured
//     reserve wallet; per-asset thresholds and caps are tier-driven.
//
//   - SmartTransfer — pick the cheapest route across configured providers
//     for a given (asset, amount, destination). Routes are scored by total
//     cost (fee + gas + slippage estimate) and the lowest-cost route wins.
//
//   - FeeBump — re-broadcast a stuck transaction with a higher fee.
//     Bitcoin: RBF (BIP-125) — replace the input UTXO set unchanged, raise
//     the explicit fee. EVM: same nonce, raise gasPrice or maxFeePerGas
//     by the configured bump factor.
//
// All three are deliberately small: they are *policies* on top of the
// existing /v1/mpc/sign + /v1/mpc/wallets/sweep primitives, not new wire
// protocols. None of them call external SaaS. They are pure-Go and rely
// only on stdlib + math/big. Wire them up by injecting:
//
//   - a Signer (an MPC-backed thing that signs transactions for a wallet)
//   - a ChainClient (anything that can read balances and broadcast txs)
//
// Both interfaces are local to this package — no cross-package coupling
// to pkg/api or pkg/mpc — so the package is testable in isolation and
// composable into any orchestrator (cron, the API scheduler, an external
// operator) without rewiring.
package automation
