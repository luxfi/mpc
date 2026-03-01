'use client'

import { useState, useEffect } from 'react'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { ChainIcon } from '@/components/common/chain-icon'
import { api, APIError } from '@/lib/api'
import type { Vault, Transaction, ClusterStatus } from '@/lib/types'

interface DashboardStats {
  vaults: number
  wallets: number
  pendingTx: number
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({ vaults: 0, wallets: 0, pendingTx: 0 })
  const [vaults, setVaults] = useState<Vault[]>([])
  const [recentTx, setRecentTx] = useState<Transaction[]>([])
  const [cluster, setCluster] = useState<ClusterStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    async function fetchDashboard() {
      try {
        const [vaultList, txList, clusterStatus] = await Promise.all([
          api.listVaults().catch(() => [] as Vault[]),
          api.listTransactions().catch(() => [] as Transaction[]),
          api.getStatus().catch(() => null),
        ])

        setVaults(vaultList)

        // Count wallets across all vaults
        let walletCount = 0
        try {
          const walletLists = await Promise.all(
            vaultList.map((v) => api.listWallets(v.id).catch(() => []))
          )
          walletCount = walletLists.reduce((sum, wl) => sum + wl.length, 0)
        } catch {
          // wallet count stays 0
        }

        const pendingCount = txList.filter(
          (tx) => tx.status === 'pending' || tx.status === 'pending_approval'
        ).length

        setStats({ vaults: vaultList.length, wallets: walletCount, pendingTx: pendingCount })
        setRecentTx(txList.slice(0, 10))
        setCluster(clusterStatus)
      } catch (err) {
        setError(err instanceof APIError ? err.message : 'Failed to load dashboard')
      } finally {
        setLoading(false)
      }
    }
    fetchDashboard()
  }, [])

  const statCards = [
    { label: 'Vaults', value: stats.vaults, description: 'Total vaults' },
    { label: 'Wallets', value: stats.wallets, description: 'Total wallets' },
    { label: 'Pending TX', value: stats.pendingTx, description: 'Awaiting approval' },
  ]

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Portfolio overview */}
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Portfolio overview and MPC cluster status.
          </p>
        </div>

        {error && (
          <div className="mb-8 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
            {error}
          </div>
        )}

        {/* Stats cards */}
        <div className="mb-8 grid gap-4 sm:grid-cols-3">
          {statCards.map((stat) => (
            <div key={stat.label} className="rounded-lg border border-border bg-card p-6">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="mt-1 text-2xl font-semibold tracking-tight font-mono">
                {loading ? '--' : stat.value}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">{stat.description}</p>
            </div>
          ))}
        </div>

        {/* Recent transactions */}
        <div className="mb-8">
          <h2 className="mb-4 text-lg font-semibold">Recent Transactions</h2>
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/50">
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Amount</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-4 py-3 text-left font-medium text-muted-foreground">Date</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                      Loading...
                    </td>
                  </tr>
                ) : recentTx.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                      No recent transactions.
                    </td>
                  </tr>
                ) : (
                  recentTx.map((tx) => (
                    <tr key={tx.id} className="border-b border-border last:border-0">
                      <td className="px-4 py-3 capitalize">{tx.tx_type}</td>
                      <td className="px-4 py-3">
                        <ChainIcon chain={tx.chain} />
                      </td>
                      <td className="px-4 py-3 font-mono">{tx.amount ?? '--'}</td>
                      <td className="px-4 py-3">
                        <StatusBadge status={tx.status} />
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">
                        {new Date(tx.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Vault summary */}
        <div className="mb-8">
          <h2 className="mb-4 text-lg font-semibold">Vault Summary</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {loading ? (
              <div className="rounded-lg border border-border bg-card p-6 text-center text-muted-foreground">
                Loading...
              </div>
            ) : vaults.length === 0 ? (
              <div className="rounded-lg border border-border bg-card p-6 text-center text-muted-foreground">
                No vaults created yet.
              </div>
            ) : (
              vaults.map((vault) => (
                <div key={vault.id} className="rounded-lg border border-border bg-card p-6">
                  <p className="font-medium">{vault.name}</p>
                  {vault.description && (
                    <p className="mt-1 text-xs text-muted-foreground">{vault.description}</p>
                  )}
                  <p className="mt-2 text-xs text-muted-foreground">
                    Created {new Date(vault.created_at).toLocaleDateString()}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* MPC Cluster Status */}
        <div>
          <h2 className="mb-4 text-lg font-semibold">MPC Cluster Status</h2>
          <div className="rounded-lg border border-border bg-card p-6">
            {loading ? (
              <p className="text-sm text-muted-foreground">Loading cluster status...</p>
            ) : cluster ? (
              <>
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Threshold</p>
                    <p className="text-lg font-semibold font-mono">
                      {cluster.threshold} of {cluster.expected_peers}
                    </p>
                  </div>
                  <StatusBadge status={cluster.ready ? 'running' : 'degraded'} />
                </div>
                <div className="space-y-3">
                  <div className="flex items-center justify-between rounded-md bg-muted/50 px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className={`h-2 w-2 rounded-full ${cluster.ready ? 'bg-emerald-400' : 'bg-yellow-400'}`} />
                      <span className="text-sm font-medium font-mono">{cluster.node_id}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-xs text-muted-foreground">
                        Peers: {cluster.connected_peers}/{cluster.expected_peers}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        v{cluster.version}
                      </span>
                      <StatusBadge status={cluster.ready ? 'running' : 'degraded'} />
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">
                Cluster status unavailable.
              </p>
            )}
          </div>
        </div>
      </main>
    </>
  )
}
