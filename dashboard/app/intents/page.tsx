'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Intent } from '@/lib/types'

const statusOptions = ['all', 'pending_sign', 'signed', 'co_signed', 'recorded', 'matched', 'settling', 'settled', 'verified', 'expired', 'failed']

export default function IntentsPage() {
  const router = useRouter()
  const [intents, setIntents] = useState<Intent[]>([])
  const [statusFilter, setStatusFilter] = useState('all')
  const [error, setError] = useState('')

  useEffect(() => {
    const filters: { status?: string } = {}
    if (statusFilter !== 'all') filters.status = statusFilter
    api.listIntents(filters).then(setIntents).catch((e) => setError(e.message))
  }, [statusFilter])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Intents</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Manage trade intents: sign, co-sign with HSM, record on-chain, and settle.
          </p>
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
        </div>

        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Amount</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Token</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Date</th>
              </tr>
            </thead>
            <tbody>
              {intents.map((intent) => (
                <tr
                  key={intent.id}
                  onClick={() => router.push(`/intents/${intent.id}`)}
                  className="cursor-pointer border-b border-border last:border-0 hover:bg-muted/30"
                >
                  <td className="px-4 py-3 capitalize">{intent.intent_type}</td>
                  <td className="px-4 py-3 capitalize">{intent.chain}</td>
                  <td className="px-4 py-3 font-mono">{intent.amount}</td>
                  <td className="px-4 py-3 font-mono text-xs">{intent.token || '--'}</td>
                  <td className="px-4 py-3"><StatusBadge status={intent.status} /></td>
                  <td className="px-4 py-3 text-muted-foreground">{new Date(intent.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
              {intents.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    No intents found.
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
