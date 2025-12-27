'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { Vault, Wallet } from '@/lib/types'

export default function BridgeWalletsPage() {
  const [config, setConfig] = useState<any>(null)
  const [vaults, setVaults] = useState<Vault[]>([])
  const [wallets, setWallets] = useState<Wallet[]>([])
  const [selectedWallet, setSelectedWallet] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    api.getBridgeConfig().then((c) => {
      setConfig(c)
      setSelectedWallet(c.signingWalletId || '')
    }).catch(() => {})
    api.listVaults().then(async (vs) => {
      setVaults(vs)
      const allWallets: Wallet[] = []
      for (const v of vs) {
        try {
          const ws = await api.listWallets(v.id)
          allWallets.push(...ws)
        } catch {}
      }
      setWallets(allWallets)
    }).catch(() => {})
  }, [])

  async function handleSave() {
    setSaving(true)
    setError('')
    setSuccess('')
    try {
      await api.updateBridgeConfig({ signing_wallet_id: selectedWallet })
      setSuccess('Bridge signing wallet updated')
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const currentWallet = wallets.find(w => w.id === selectedWallet || w.wallet_id === selectedWallet)

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/bridge" className="hover:text-foreground">Bridge</Link>
          <span>/</span>
          <span>Signing Wallets</span>
        </div>

        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Bridge Signing Wallet</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Select which MPC wallet is used to sign bridge transactions.
          </p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}
        {success && <p className="mb-4 text-sm text-green-500">{success}</p>}

        <div className="mb-8 rounded-lg border border-border bg-card p-6">
          <h2 className="mb-4 text-lg font-semibold">Select Wallet</h2>
          <div className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">MPC Wallet</label>
              <select
                value={selectedWallet}
                onChange={(e) => setSelectedWallet(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">-- Select a wallet --</option>
                {wallets.map(w => (
                  <option key={w.id} value={w.id}>
                    {w.name || w.wallet_id.slice(0, 12)} — {w.eth_address?.slice(0, 10)}...
                  </option>
                ))}
              </select>
            </div>
            <button
              onClick={handleSave}
              disabled={saving}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>

        {currentWallet && (
          <div className="rounded-lg border border-border bg-card p-6">
            <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Current Wallet Addresses</h2>
            <dl className="grid gap-4 sm:grid-cols-2">
              {currentWallet.eth_address && (
                <div>
                  <dt className="text-xs text-muted-foreground">Ethereum / EVM</dt>
                  <dd className="mt-1 font-mono text-xs break-all">{currentWallet.eth_address}</dd>
                </div>
              )}
              {currentWallet.btc_address && (
                <div>
                  <dt className="text-xs text-muted-foreground">Bitcoin</dt>
                  <dd className="mt-1 font-mono text-xs break-all">{currentWallet.btc_address}</dd>
                </div>
              )}
              {currentWallet.sol_address && (
                <div>
                  <dt className="text-xs text-muted-foreground">Solana</dt>
                  <dd className="mt-1 font-mono text-xs break-all">{currentWallet.sol_address}</dd>
                </div>
              )}
              <div>
                <dt className="text-xs text-muted-foreground">Protocol</dt>
                <dd className="mt-1 text-sm capitalize">{currentWallet.protocol || 'cggmp21'}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Threshold</dt>
                <dd className="mt-1 text-sm">{currentWallet.threshold}-of-{currentWallet.participants?.length || '?'}</dd>
              </div>
            </dl>
          </div>
        )}
      </main>
    </>
  )
}
