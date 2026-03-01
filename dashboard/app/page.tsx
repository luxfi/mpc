import Link from 'next/link'

const features = [
  {
    title: 'MPC Key Generation',
    description:
      'CGGMP21 (ECDSA) and FROST (EdDSA) threshold keygen. No single point of failure — shares are distributed, never reconstructed.',
  },
  {
    title: 'Policy Engine',
    description:
      'Per-vault spend limits, address allowlists, time-window controls, and multi-approver quorum rules enforced before signing.',
  },
  {
    title: 'Multi-Chain',
    description:
      'Ethereum, Bitcoin (Taproot), Solana, Lux, and any EVM chain. One key pair covers all networks simultaneously.',
  },
  {
    title: 'Transaction Approvals',
    description:
      'Role-based approval flows — Viewer, Signer, Admin, Owner. Transactions queue for human review before the cluster signs.',
  },
  {
    title: 'Dynamic Resharing (LSS)',
    description:
      'Change threshold or rotate participants without changing on-chain addresses. Zero downtime key rotation.',
  },
  {
    title: 'Audit Log & Webhooks',
    description:
      'Immutable audit trail for every action. Real-time webhooks for transaction events, approvals, and cluster health.',
  },
  {
    title: 'Safe & ERC-4337 Support',
    description:
      'Deploy Gnosis Safe or ERC-4337 smart accounts with the MPC EOA as signer. Use session keys for recurring payments.',
  },
  {
    title: 'Recurring Subscriptions',
    description:
      'Schedule automated payments daily, weekly, or monthly. Scheduler checks balances, signs, and broadcasts on your behalf.',
  },
]

const chains = ['Ethereum', 'Bitcoin', 'Lux', 'Solana', 'Polygon', 'Arbitrum', 'Base', 'Avalanche']

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Top nav */}
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="h-7 w-7 rounded bg-primary" />
            <span className="text-lg font-semibold tracking-tight">Lux MPC</span>
          </div>
          <nav className="hidden items-center gap-6 text-sm text-muted-foreground sm:flex">
            <a href="#features" className="transition-colors hover:text-foreground">
              Features
            </a>
            <a href="#chains" className="transition-colors hover:text-foreground">
              Chains
            </a>
            <a href="#docs" className="transition-colors hover:text-foreground">
              Docs
            </a>
          </nav>
          <div className="flex items-center gap-3">
            <Link
              href="/login"
              className="text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              Sign in
            </Link>
            <Link
              href="/register"
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
            >
              Get started
            </Link>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="mx-auto max-w-7xl px-4 pb-20 pt-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs text-muted-foreground">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            CGGMP21 · FROST · LSS resharing
          </div>
          <h1 className="text-4xl font-semibold tracking-tight sm:text-5xl lg:text-6xl">
            Enterprise MPC Wallet Infrastructure
          </h1>
          <p className="mt-6 text-lg text-muted-foreground">
            Threshold multi-party computation wallets with a full policy engine, approval flows,
            team roles, and a real-time dashboard — built to compete with Fireblocks, Utila, and
            Fordefi.
          </p>
          <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
            <Link
              href="/register"
              className="w-full rounded-md bg-primary px-6 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 sm:w-auto"
            >
              Create account
            </Link>
            <Link
              href="/login"
              className="w-full rounded-md border border-border bg-card px-6 py-3 text-sm font-medium transition-colors hover:bg-muted sm:w-auto"
            >
              Open dashboard
            </Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="border-t border-border bg-muted/20 py-20">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <h2 className="mb-12 text-center text-2xl font-semibold tracking-tight">
            Everything you need to run MPC wallets in production
          </h2>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {features.map((f) => (
              <div key={f.title} className="rounded-lg border border-border bg-card p-6">
                <p className="mb-2 font-medium">{f.title}</p>
                <p className="text-sm text-muted-foreground">{f.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Supported chains */}
      <section id="chains" className="py-20">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <h2 className="mb-10 text-center text-2xl font-semibold tracking-tight">
            Supported networks
          </h2>
          <div className="flex flex-wrap justify-center gap-3">
            {chains.map((chain) => (
              <span
                key={chain}
                className="rounded-full border border-border bg-card px-4 py-2 text-sm font-medium"
              >
                {chain}
              </span>
            ))}
          </div>
          <p className="mt-6 text-center text-sm text-muted-foreground">
            Any EVM-compatible chain is supported via configurable RPC endpoints.
          </p>
        </div>
      </section>

      {/* Docs */}
      <section id="docs" className="border-t border-border bg-muted/20 py-20">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="mb-4 text-2xl font-semibold tracking-tight">Developer docs</h2>
            <p className="mb-8 text-muted-foreground">
              Integrate MPC signing into your application via REST API or go-client. Full OpenAPI
              spec and SDK examples included.
            </p>
            <div className="overflow-hidden rounded-lg border border-border bg-card text-left">
              <div className="border-b border-border bg-muted/50 px-4 py-2.5 text-xs font-medium text-muted-foreground">
                Quick start — create wallet via API
              </div>
              <pre className="overflow-x-auto p-4 text-xs leading-relaxed text-foreground/80">
                <code>{`# Create vault
curl -X POST https://mpc.lux.network/api/v1/vaults \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{"name":"Treasury"}'

# Generate MPC wallet (triggers keygen)
curl -X POST https://mpc.lux.network/api/v1/vaults/$VAULT_ID/wallets \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{"name":"Main","key_type":"secp256k1","threshold":2,"participants":["node0","node1","node2"]}'

# Sign a transaction
curl -X POST https://mpc.lux.network/api/v1/transactions \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{"wallet_id":"...","chain":"ethereum","to":"0x...","amount":"1.5"}'`}</code>
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20">
        <div className="mx-auto max-w-7xl px-4 text-center sm:px-6 lg:px-8">
          <h2 className="mb-4 text-2xl font-semibold tracking-tight">
            Ready to secure your assets?
          </h2>
          <p className="mb-8 text-muted-foreground">
            Self-hosted or managed — Lux MPC runs on your infrastructure.
          </p>
          <Link
            href="/register"
            className="inline-flex rounded-md bg-primary px-8 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
          >
            Get started for free
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-10">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 text-sm text-muted-foreground sm:flex-row sm:px-6 lg:px-8">
          <div className="flex items-center gap-2">
            <div className="h-5 w-5 rounded bg-primary/80" />
            <span>Lux MPC · Lux Network</span>
          </div>
          <div className="flex gap-6">
            <Link href="/login" className="hover:text-foreground">
              Sign in
            </Link>
            <Link href="/register" className="hover:text-foreground">
              Register
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
