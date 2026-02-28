'use client'

import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { ChainIcon } from '@/components/common/chain-icon'

const stats = [
  { label: 'Vaults', value: '--', description: 'Total vaults' },
  { label: 'Wallets', value: '--', description: 'Total wallets' },
  { label: 'Pending TX', value: '--', description: 'Awaiting approval' },
]

const recentTx: {
  id: string
  type: string
  chain: string
  amount: string
  status: string
  created_at: string
}[] = []

const clusterNodes = [
  { id: 'node0', status: 'running', uptime: '99.9%' },
  { id: 'node1', status: 'running', uptime: '99.8%' },
  { id: 'node2', status: 'running', uptime: '99.7%' },
]

export default function DashboardPage() {
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

        {/* Total value */}
        <div className="mb-8 rounded-lg border border-border bg-card p-6">
          <p className="text-sm text-muted-foreground">Total Portfolio Value</p>
          <p className="mt-1 text-3xl font-semibold tracking-tight font-mono">$--,---.--</p>
        </div>

        {/* Stats cards */}
        <div className="mb-8 grid gap-4 sm:grid-cols-3">
          {stats.map((stat) => (
            <div key={stat.label} className="rounded-lg border border-border bg-card p-6">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="mt-1 text-2xl font-semibold tracking-tight font-mono">{stat.value}</p>
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
                {recentTx.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                      No recent transactions.
                    </td>
                  </tr>
                ) : (
                  recentTx.map((tx) => (
                    <tr key={tx.id} className="border-b border-border last:border-0">
                      <td className="px-4 py-3 capitalize">{tx.type}</td>
                      <td className="px-4 py-3">
                        <ChainIcon chain={tx.chain} />
                      </td>
                      <td className="px-4 py-3 font-mono">{tx.amount}</td>
                      <td className="px-4 py-3">
                        <StatusBadge status={tx.status} />
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">{tx.created_at}</td>
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
            <div className="rounded-lg border border-border bg-card p-6 text-center text-muted-foreground">
              No vaults created yet.
            </div>
          </div>
        </div>

        {/* MPC Cluster Status */}
        <div>
          <h2 className="mb-4 text-lg font-semibold">MPC Cluster Status</h2>
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Threshold</p>
                <p className="text-lg font-semibold font-mono">2 of 3</p>
              </div>
              <StatusBadge status="running" />
            </div>
            <div className="space-y-3">
              {clusterNodes.map((node) => (
                <div
                  key={node.id}
                  className="flex items-center justify-between rounded-md bg-muted/50 px-4 py-3"
                >
                  <div className="flex items-center gap-3">
                    <div className="h-2 w-2 rounded-full bg-emerald-400" />
                    <span className="text-sm font-medium font-mono">{node.id}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-xs text-muted-foreground">Uptime: {node.uptime}</span>
                    <StatusBadge status={node.status} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </>
  )
}
