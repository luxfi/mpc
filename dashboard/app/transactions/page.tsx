'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Transaction } from '@/lib/types'

const statusOptions = ['all', 'pending', 'pending_approval', 'approved', 'signing', 'signed', 'broadcast', 'failed', 'rejected']
const chainOptions = ['all', 'ethereum', 'bitcoin', 'lux', 'solana', 'xrpl']

export default function TransactionsPage() {
  const router = useRouter()
  const [transactions, setTransactions] = useState<Transaction[]>([])
  const [statusFilter, setStatusFilter] = useState('all')
  const [chainFilter, setChainFilter] = useState('all')
  const [error, setError] = useState('')

  useEffect(() => {
    const filters: { status?: string; chain?: string } = {}
    if (statusFilter !== 'all') filters.status = statusFilter
    if (chainFilter !== 'all') filters.chain = chainFilter
    api.listTransactions(filters).then(setTransactions).catch((e) => setError(e.message))
  }, [statusFilter, chainFilter])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Transactions</h1>
          <p className="mt-1 text-sm text-muted-foreground">View and manage all transactions.</p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        {/* Filters */}
        <div className="mb-6 flex flex-wrap items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            {statusOptions.map((s) => (
              <option key={s} value={s}>{s === 'all' ? 'All Status' : s.replace(/_/g, ' ')}</option>
            ))}
          </select>
          <select
            value={chainFilter}
            onChange={(e) => setChainFilter(e.target.value)}
            className="rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            {chainOptions.map((c) => (
              <option key={c} value={c}>{c === 'all' ? 'All Chains' : c}</option>
            ))}
          </select>
        </div>

        {/* Table */}
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
                <tr
                  key={tx.id}
                  onClick={() => router.push(`/transactions/${tx.id}`)}
                  className="cursor-pointer border-b border-border last:border-0 hover:bg-muted/30"
                >
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
                    No transactions found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </main>
    </>
  )
}
