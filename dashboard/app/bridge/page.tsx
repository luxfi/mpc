'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'

export default function BridgePage() {
  const [config, setConfig] = useState<any>(null)
  const [networks, setNetworks] = useState<any[]>([])

  useEffect(() => {
    api.getBridgeConfig().then(setConfig).catch(() => {})
    api.listBridgeNetworks().then(setNetworks).catch(() => {})
  }, [])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Bridge Administration</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Configure the cross-chain bridge: wallets, fees, and contracts.
          </p>
        </div>

        {/* Overview cards */}
        <div className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-border bg-card p-6">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Signing Wallet</p>
            <p className="mt-2 font-mono text-sm">
              {config?.signingWalletId ? config.signingWalletId.slice(0, 12) + '...' : 'Not configured'}
            </p>
          </div>
          <div className="rounded-lg border border-border bg-card p-6">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Fee Rate</p>
            <p className="mt-2 text-lg font-semibold">{config ? (config.feeRateBps / 100).toFixed(2) : '--'}%</p>
          </div>
          <div className="rounded-lg border border-border bg-card p-6">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Deposits</p>
            <p className="mt-2 text-sm font-medium">
              <span className={config?.depositsEnabled ? 'text-green-500' : 'text-red-500'}>
                {config?.depositsEnabled ? 'Enabled' : 'Disabled'}
              </span>
            </p>
          </div>
          <div className="rounded-lg border border-border bg-card p-6">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Withdrawals</p>
            <p className="mt-2 text-sm font-medium">
              <span className={config?.withdrawalsEnabled ? 'text-green-500' : 'text-red-500'}>
                {config?.withdrawalsEnabled ? 'Enabled' : 'Disabled'}
              </span>
            </p>
          </div>
        </div>

        {/* Sub-pages */}
        <div className="mb-8 grid gap-4 sm:grid-cols-3">
          <Link
            href="/bridge/wallets"
            className="group rounded-lg border border-border bg-card p-6 transition-colors hover:border-foreground/20"
          >
            <h3 className="font-semibold group-hover:text-foreground">Signing Wallets</h3>
            <p className="mt-1 text-sm text-muted-foreground">Select and manage MPC wallets used for bridge signing.</p>
          </Link>
          <Link
            href="/bridge/fees"
            className="group rounded-lg border border-border bg-card p-6 transition-colors hover:border-foreground/20"
          >
            <h3 className="font-semibold group-hover:text-foreground">Fee Configuration</h3>
            <p className="mt-1 text-sm text-muted-foreground">Set fee rates, collector addresses, and per-network overrides.</p>
          </Link>
          <Link
            href="/bridge/contracts"
            className="group rounded-lg border border-border bg-card p-6 transition-colors hover:border-foreground/20"
          >
            <h3 className="font-semibold group-hover:text-foreground">Contracts</h3>
            <p className="mt-1 text-sm text-muted-foreground">Manage bridge token contracts and BRIDGE_ROLE grants.</p>
          </Link>
        </div>

        {/* Networks */}
        <div className="rounded-lg border border-border bg-card p-6">
          <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Supported Networks</h2>
          <div className="space-y-2">
            {networks.map((net) => (
              <div
                key={net.chain}
                className="flex items-center justify-between rounded-md border border-border px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium">{net.name}</span>
                  <span className="rounded-md bg-muted/50 px-2 py-0.5 font-mono text-xs text-muted-foreground">{net.type}</span>
                </div>
                <div className="flex gap-4 text-xs">
                  <span className={net.deposit ? 'text-green-500' : 'text-muted-foreground'}>
                    Deposit: {net.deposit ? 'ON' : 'OFF'}
                  </span>
                  <span className={net.withdrawal ? 'text-green-500' : 'text-muted-foreground'}>
                    Withdrawal: {net.withdrawal ? 'ON' : 'OFF'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </>
  )
}
