import Link from 'next/link'

const sections = [
  {
    title: 'Introduction',
    description: 'Overview of the Lux MPC threshold signing service, architecture, and core concepts.',
    color: 'border-violet-500/30',
  },
  {
    title: 'Quick Start',
    description: 'Get up and running in minutes — create a vault, generate a wallet, and sign your first transaction.',
    color: 'border-blue-500/30',
  },
  {
    title: 'Installation',
    description: 'Deploy MPC nodes via Docker, Kubernetes, or build from source. Configuration and networking setup.',
    color: 'border-cyan-500/30',
  },
  {
    title: 'Protocol Overview',
    description: 'Deep dive into CGGMP21 (ECDSA) and FROST (EdDSA) threshold signing protocols.',
    color: 'border-emerald-500/30',
  },
  {
    title: 'API Reference',
    description: 'Complete REST API documentation — authentication, wallets, transactions, bridge, and webhooks.',
    color: 'border-amber-500/30',
  },
  {
    title: 'Security Model',
    description: 'Threat model, key management, HSM integration, audit logging, and compliance considerations.',
    color: 'border-rose-500/30',
  },
  {
    title: 'Use Cases',
    description: 'Institutional custody, cross-chain bridges, smart wallet automation, and recurring payments.',
    color: 'border-purple-500/30',
  },
]

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-16">
      <Link
        href="/"
        className="mb-8 inline-flex items-center text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        &larr; Back to home
      </Link>

      <h1 className="text-4xl font-bold tracking-tight">Documentation</h1>
      <p className="mt-3 text-lg text-muted-foreground">
        Everything you need to integrate with the Lux MPC threshold signing service.
      </p>

      <div className="mt-12 grid gap-4 sm:grid-cols-2">
        {sections.map((s) => (
          <div
            key={s.title}
            className={`rounded-xl border ${s.color} bg-card p-6 transition-colors hover:bg-card/80`}
          >
            <h3 className="mb-2 font-semibold">{s.title}</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              {s.description}
            </p>
          </div>
        ))}
      </div>

      <div className="mt-12 rounded-xl border border-border bg-card p-6">
        <h2 className="mb-3 text-lg font-semibold">API Base URL</h2>
        <code className="rounded bg-background px-3 py-1.5 text-sm text-violet-400">
          https://mpc-api.lux.network/api/v1
        </code>
        <p className="mt-3 text-sm text-muted-foreground">
          Authenticate with JWT (via Lux ID / Pars ID / Zoo ID) or API keys.
          All endpoints require the <code className="text-violet-400">Authorization: Bearer &lt;token&gt;</code> header
          or <code className="text-violet-400">X-API-Key: &lt;key&gt;</code> header.
        </p>
      </div>

      <div className="mt-8 rounded-xl border border-border bg-card p-6">
        <h2 className="mb-3 text-lg font-semibold">Supported Chains</h2>
        <div className="flex flex-wrap gap-2">
          {['Bitcoin', 'Ethereum', 'Lux', 'Solana', 'XRPL', 'TON', 'Polygon', 'Arbitrum', 'Base', 'BNB'].map((c) => (
            <span
              key={c}
              className="rounded-full border border-violet-500/20 bg-violet-500/10 px-3 py-1 text-xs font-medium text-violet-300"
            >
              {c}
            </span>
          ))}
        </div>
      </div>

      <div className="mt-8 rounded-xl border border-border bg-card p-6">
        <h2 className="mb-3 text-lg font-semibold">Quick Example</h2>
        <pre className="overflow-x-auto rounded-lg bg-background p-4 text-sm leading-relaxed">
          <code>{`# 1. Authenticate
curl -X POST https://mpc-api.lux.network/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"you@example.com","password":"..."}'

# 2. Create a vault
curl -X POST https://mpc-api.lux.network/api/v1/vaults \\
  -H "Authorization: Bearer <token>" \\
  -d '{"name":"My Vault"}'

# 3. Generate a wallet (triggers MPC keygen across 5 nodes)
curl -X POST https://mpc-api.lux.network/api/v1/vaults/<id>/wallets \\
  -H "Authorization: Bearer <token>" \\
  -d '{"name":"my-wallet","curve":"secp256k1","protocol":"cggmp21"}'

# 4. Sign a transaction (3-of-5 threshold signature)
curl -X POST https://mpc-api.lux.network/api/v1/transactions \\
  -H "Authorization: Bearer <token>" \\
  -d '{"wallet_id":"<id>","tx_type":"transfer","chain":"ethereum",...}'`}</code>
        </pre>
      </div>
    </div>
  )
}
