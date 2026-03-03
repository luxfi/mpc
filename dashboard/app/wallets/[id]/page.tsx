'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Wallet, WalletAddresses, Transaction, WalletBackup } from '@/lib/types'

export default function WalletDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [wallet, setWallet] = useState<Wallet | null>(null)
  const [addresses, setAddresses] = useState<WalletAddresses | null>(null)
  const [transactions, setTransactions] = useState<Transaction[]>([])
  const [backups, setBackups] = useState<WalletBackup[]>([])
  const [creatingBackup, setCreatingBackup] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) return
    api.getWallet(id).then(setWallet).catch((e) => setError(e.message))
    api.getWalletAddresses(id).then(setAddresses).catch(() => {})
    api.getWalletHistory(id).then(setTransactions).catch(() => {})
    api.getWalletBackups(id).then(setBackups).catch(() => {})
  }, [id])

  async function handleCreateBackup() {
    setCreatingBackup(true)
    try {
      await api.createWalletBackup(id)
      const updated = await api.getWalletBackups(id)
      setBackups(updated)
    } catch {
      // handled by API client
    } finally {
      setCreatingBackup(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/vaults" className="hover:text-foreground">Vaults</Link>
          <span>/</span>
          <span>Wallet</span>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        {wallet && (
          <>
            {/* Header */}
            <div className="mb-8 flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold tracking-tight">
                  {wallet.name || 'Unnamed Wallet'}
                </h1>
                <p className="mt-1 text-sm text-muted-foreground">
                  <span className="font-mono">{wallet.key_type}</span>
                  {' -- '}
                  <span className="capitalize">{wallet.protocol || 'cggmp21'}</span>
                  {' -- '}
                  Threshold: {wallet.threshold} of {wallet.participants.length}
                </p>
                <div className="mt-2">
                  <StatusBadge status={wallet.status} />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Link
                  href={`/wallets/${id}/reshare`}
                  className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent"
                >
                  Reshare
                </Link>
                <Link
                  href={`/wallets/${id}/smart-wallets`}
                  className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent"
                >
                  Smart Wallets
                </Link>
                <Link
                  href={`/wallets/${id}/send`}
                  className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                >
                  Send
                </Link>
              </div>
            </div>

            {/* Wallet Info */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium text-muted-foreground">Wallet Info</h2>
              <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
                <div>
                  <dt className="text-muted-foreground">Wallet ID</dt>
                  <dd className="mt-1 font-mono text-xs">{wallet.wallet_id}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Key Type</dt>
                  <dd className="mt-1 font-mono">{wallet.key_type}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Threshold</dt>
                  <dd className="mt-1">{wallet.threshold} of {wallet.participants.length}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Version</dt>
                  <dd className="mt-1">{wallet.version}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Created</dt>
                  <dd className="mt-1">{new Date(wallet.created_at).toLocaleDateString()}</dd>
                </div>
              </dl>

              {/* Participants */}
              <div className="mt-6">
                <h3 className="mb-2 text-sm font-medium text-muted-foreground">Participants</h3>
                <div className="flex flex-wrap gap-2">
                  {wallet.participants.map((p) => (
                    <span key={p} className="rounded-md border border-border bg-muted/50 px-2 py-1 font-mono text-xs">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* Addresses */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium text-muted-foreground">Addresses</h2>
              <div className="space-y-3">
                {(wallet.eth_address || addresses?.ethereum) && (
                  <div className="rounded-md bg-muted/50 px-4 py-3">
                    <p className="text-xs text-muted-foreground">Ethereum / EVM</p>
                    <p className="font-mono text-sm">{wallet.eth_address || addresses?.ethereum}</p>
                  </div>
                )}
                {(wallet.btc_address || addresses?.bitcoin) && (
                  <div className="rounded-md bg-muted/50 px-4 py-3">
                    <p className="text-xs text-muted-foreground">Bitcoin</p>
                    <p className="font-mono text-sm">{wallet.btc_address || addresses?.bitcoin}</p>
                  </div>
                )}
                {(wallet.sol_address || addresses?.solana) && (
                  <div className="rounded-md bg-muted/50 px-4 py-3">
                    <p className="text-xs text-muted-foreground">Solana</p>
                    <p className="font-mono text-sm">{wallet.sol_address || addresses?.solana}</p>
                  </div>
                )}
                {!wallet.eth_address && !wallet.btc_address && !wallet.sol_address &&
                 !addresses?.ethereum && !addresses?.bitcoin && !addresses?.solana && (
                  <p className="text-sm text-muted-foreground">No addresses generated yet.</p>
                )}
              </div>
            </div>

            {/* Key Backup */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Key Backup (Shamir)</h2>
                <button
                  onClick={handleCreateBackup}
                  disabled={creatingBackup}
                  className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent disabled:opacity-50"
                >
                  {creatingBackup ? 'Creating...' : 'Create Backup'}
                </button>
              </div>
              {backups.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No backups yet. Create a Shamir secret-shared backup to enable recovery.
                </p>
              ) : (
                <div className="space-y-3">
                  {backups.map((b) => (
                    <div key={b.id} className="rounded-md border border-border bg-muted/30 p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium">
                            {b.threshold}-of-{b.total_shards} Shamir Split
                          </p>
                          <p className="text-xs text-muted-foreground font-mono">{b.backup_id}</p>
                        </div>
                        <StatusBadge status={b.status} />
                      </div>
                      {b.shards && b.shards.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-2">
                          {b.shards.map((shard) => (
                            <span
                              key={shard.index}
                              className={`rounded-md border px-2 py-1 text-xs font-medium capitalize ${
                                shard.verified_at
                                  ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                                  : 'border-border bg-muted/50 text-muted-foreground'
                              }`}
                            >
                              Shard {shard.index}: {shard.destination}
                              {shard.verified_at && ' (verified)'}
                            </span>
                          ))}
                        </div>
                      )}
                      <p className="mt-2 text-xs text-muted-foreground">
                        Created {new Date(b.created_at).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recent Transactions */}
            <h2 className="mb-4 text-lg font-semibold">Recent Transactions</h2>
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/50">
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">To</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Amount</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {transactions.map((tx) => (
                    <tr key={tx.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                      <td className="px-4 py-3 capitalize">{tx.tx_type}</td>
                      <td className="px-4 py-3 capitalize">{tx.chain}</td>
                      <td className="px-4 py-3 font-mono text-xs">
                        {tx.to_address ? `${tx.to_address.slice(0, 10)}...${tx.to_address.slice(-6)}` : '--'}
                      </td>
                      <td className="px-4 py-3 font-mono">{tx.amount || '--'}</td>
                      <td className="px-4 py-3"><StatusBadge status={tx.status} /></td>
                      <td className="px-4 py-3 text-muted-foreground">{new Date(tx.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
                  {transactions.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                        No transactions yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {!wallet && !error && (
          <p className="text-sm text-muted-foreground">Loading...</p>
        )}
      </main>
    </>
  )
}
