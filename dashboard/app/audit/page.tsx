'use client'

import { useState, useEffect } from 'react'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { AuditEntry } from '@/lib/types'

export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    api.listAudit().then(setEntries).catch((e) => setError(e.message))
  }, [])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Audit Log</h1>
          <p className="mt-1 text-sm text-muted-foreground">Track all actions performed in the system.</p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Action</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Resource</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">User</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Date</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">IP</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id} className="border-b border-border last:border-0">
                  <td className="px-4 py-3 font-medium">{entry.action}</td>
                  <td className="px-4 py-3">
                    {entry.resource_type && (
                      <span className="text-muted-foreground">
                        {entry.resource_type}
                        {entry.resource_id && (
                          <span className="ml-1 font-mono text-xs">{entry.resource_id.slice(0, 12)}...</span>
                        )}
                      </span>
                    )}
                    {!entry.resource_type && <span className="text-muted-foreground">--</span>}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                    {entry.user_id || '--'}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(entry.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                    {entry.ip_address || '--'}
                  </td>
                </tr>
              ))}
              {entries.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                    No audit entries.
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
