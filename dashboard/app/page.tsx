'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { getBranding, type Branding } from '@/lib/branding'

const CALLBACK_PATH = '/auth/callback'

function buildLoginUrl(branding: Branding): string {
  const redirectUri = `${window.location.origin}${CALLBACK_PATH}`
  const state = crypto.randomUUID()
  sessionStorage.setItem('oidc_state', state)

  const params = new URLSearchParams({
    response_type: 'token',
    client_id: branding.iamClientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
  })

  return `${branding.iamUrl}/oauth/authorize?${params.toString()}`
}

const features = [
  {
    title: 'CGGMP21',
    description: '5-round threshold ECDSA (secp256k1) for Bitcoin, Ethereum, Lux, XRPL, and all EVM chains.',
    color: 'text-violet-400',
  },
  {
    title: 'FROST',
    description: '2-round threshold EdDSA (Ed25519) for Solana, TON. BIP-340 Schnorr for Bitcoin Taproot.',
    color: 'text-blue-400',
  },
  {
    title: 'Bridge',
    description: 'Cross-chain asset bridge with MPC-signed transactions. Multi-network, policy-driven approvals.',
    color: 'text-emerald-400',
  },
]

const chains = [
  'Bitcoin', 'Ethereum', 'Lux', 'Solana', 'XRPL', 'TON',
  'Polygon', 'Arbitrum', 'Base', 'BNB',
]

export default function LandingPage() {
  const [branding, setBranding] = useState<Branding>(getBranding(''))
  const [hasSession, setHasSession] = useState(false)

  useEffect(() => {
    setBranding(getBranding(window.location.hostname))
    setHasSession(document.cookie.includes('lux_mpc_session'))
  }, [])

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-16">
      <div className="w-full max-w-3xl text-center">
        {/* Hero */}
        <h1 className="bg-gradient-to-r from-violet-500 to-blue-500 bg-clip-text text-5xl font-bold tracking-tight text-transparent sm:text-6xl">
          {branding.brand}
        </h1>
        <p className="mt-3 text-lg text-muted-foreground">
          Threshold Signing Service &bull; 3-of-5 Consensus
        </p>

        {/* CTA */}
        <div className="mt-8 flex items-center justify-center gap-4">
          {hasSession ? (
            <Link
              href="/dashboard"
              className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              Go to Dashboard
            </Link>
          ) : (
            <button
              type="button"
              onClick={() => { window.location.href = buildLoginUrl(branding) }}
              className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              Sign in with {branding.iamLabel}
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
              className="rounded-full border border-violet-500/20 bg-violet-500/10 px-3 py-1 text-xs font-medium text-violet-300"
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
