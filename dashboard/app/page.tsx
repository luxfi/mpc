// Lux is MONOCHROME. This page used to be the loudest exception in the fleet:
// a violet→blue gradient wordmark, three feature headings in violet / blue /
// emerald, and ten chain chips on a violet wash — 1.05% of every rendered pixel
// carrying hue #ece7f7, on a surface whose dashboard next door is achromatic.
//
// Distinction here is carried by the LABEL, which already said CGGMP21 / FROST /
// Bridge. Every colour resolves through a token now, so white-label-by-hostname
// retints it without a rebuild.
'use client'

import { startLogin } from '@hanzo/iam/browser'
import { useIdentity, useWhiteLabel } from '@luxfi/ui'
import Link from 'next/link'

const features = [
  {
    title: 'CGGMP21',
    description: '5-round threshold ECDSA (secp256k1) for Bitcoin, Ethereum, Lux, XRPL, and all EVM chains.',
    color: 'text-foreground',
  },
  {
    title: 'FROST',
    description: '2-round threshold EdDSA (Ed25519) for Solana, TON. BIP-340 Schnorr for Bitcoin Taproot.',
    color: 'text-foreground',
  },
  {
    title: 'Bridge',
    description: 'Cross-chain asset bridge with MPC-signed transactions. Multi-network, policy-driven approvals.',
    color: 'text-foreground',
  },
]

const chains = [
  'Bitcoin', 'Ethereum', 'Lux', 'Solana', 'XRPL', 'TON',
  'Polygon', 'Arbitrum', 'Base', 'BNB',
]

export default function LandingPage() {
  const wl = useWhiteLabel()
  // "Am I signed in?" is IAM's answer, read through the shared identity — not a
  // cookie sniff that only ever reflected the MPC API's own exchange.
  const { status } = useIdentity()

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-16">
      <div className="w-full max-w-3xl text-center">
        {/* Hero */}
        <h1 className="text-5xl font-bold tracking-tight text-foreground sm:text-6xl">
          {wl.name} MPC
        </h1>
        <p className="mt-3 text-lg text-muted-foreground">
          Threshold Signing Service &bull; 3-of-5 Consensus
        </p>

        {/* CTA */}
        <div className="mt-8 flex items-center justify-center gap-4">
          {status === 'ready' ? (
            <Link
              href="/dashboard"
              className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              Go to Dashboard
            </Link>
          ) : (
            <button
              type="button"
              onClick={() => void startLogin({ redirect: '/dashboard' })}
              className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              Sign in with {wl.iamDomain}
            </button>
          )}
          <Link
            href="/docs"
            className="rounded-lg border border-border px-6 py-2.5 text-sm font-medium text-foreground transition-colors hover:bg-card"
          >
            Documentation
          </Link>
        </div>

        {/* Feature cards */}
        <div className="mt-16 grid gap-4 sm:grid-cols-3">
          {features.map((f) => (
            <div
              key={f.title}
              className="rounded-xl border border-border bg-card p-6 text-left"
            >
              <h3 className={`mb-2 text-sm font-semibold ${f.color}`}>
                {f.title}
              </h3>
              <p className="text-sm leading-relaxed text-muted-foreground">
                {f.description}
              </p>
            </div>
          ))}
        </div>

        {/* Chain chips */}
        <div className="mt-10 flex flex-wrap items-center justify-center gap-2">
          {chains.map((c) => (
            <span
              key={c}
              className="rounded-full border border-border bg-muted px-3 py-1 text-xs font-medium text-muted-foreground"
            >
              {c}
            </span>
          ))}
        </div>

        {/* Footer links */}
        <div className="mt-12 flex flex-wrap items-center justify-center gap-4 text-sm">
          <a href="/healthz" className="text-muted-foreground transition-colors hover:text-foreground">
            API Status
          </a>
          <a href="https://bridge.lux.network" className="text-muted-foreground transition-colors hover:text-foreground">
            Bridge Dashboard
          </a>
          <a href="/api/v1/bridge/networks" className="text-muted-foreground transition-colors hover:text-foreground">
            Networks
          </a>
        </div>

        <p className="mt-8 text-xs text-muted-foreground/60">
          v0.3.3 &bull; Post-Quantum TLS 1.3 &bull; ZapDB Encrypted Storage
        </p>
      </div>
    </div>
  )
}
