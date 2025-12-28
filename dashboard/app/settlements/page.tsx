'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Settlement } from '@/lib/types'

const statusOptions = ['all', 'pending', 'hsm_signing', 'broadcast', 'confirming', 'finalized', 'verified', 'failed']

export default function SettlementsPage() {
  const router = useRouter()
  const [settlements, setSettlements] = useState<Settlement[]>([])
  const [statusFilter, setStatusFilter] = useState('all')
  const [error, setError] = useState('')

  useEffect(() => {
    const filters: { status?: string } = {}
    if (statusFilter !== 'all') filters.status = statusFilter
    api.listSettlements(filters).then(setSettlements).catch((e) => setError(e.message))
  }, [statusFilter])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Settlements</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Track settlement lifecycle: HSM signing, broadcast, finalization, and transfer agency verification.
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
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Settlement ID</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Intent</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">HSM Sigs</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Verified</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Date</th>
              </tr>
            </thead>
            <tbody>
              {settlements.map((s) => (
                <tr
                  key={s.id}
                  onClick={() => router.push(`/settlements/${s.id}`)}
                  className="cursor-pointer border-b border-border last:border-0 hover:bg-muted/30"
                >
                  <td className="px-4 py-3 font-mono text-xs">{s.id.slice(0, 12)}...</td>
                  <td className="px-4 py-3 font-mono text-xs">{s.intent_id.slice(0, 12)}...</td>
                  <td className="px-4 py-3">{s.hsm_signatures?.length || 0}</td>
                  <td className="px-4 py-3">
                    {s.transfer_agency_verified ? (
                      <span className="text-emerald-400">Yes</span>
                    ) : (
                      <span className="text-muted-foreground">No</span>
                    )}
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={s.status} /></td>
                  <td className="px-4 py-3 text-muted-foreground">{new Date(s.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
              {settlements.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    No settlements found.
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
