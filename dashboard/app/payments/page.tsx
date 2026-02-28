'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { PaymentRequest } from '@/lib/types'

export default function PaymentsPage() {
  const [payments, setPayments] = useState<PaymentRequest[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    api.listPaymentRequests().then(setPayments).catch((e) => setError(e.message))
  }, [])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Payment Requests</h1>
            <p className="mt-1 text-sm text-muted-foreground">Create and manage payment requests.</p>
          </div>
          <Link
            href="/payments/new"
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Create Payment Request
          </Link>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Merchant</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Amount</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Created</th>
              </tr>
            </thead>
            <tbody>
              {payments.map((pr) => (
                <tr key={pr.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="px-4 py-3 font-medium">{pr.merchant_name || '--'}</td>
                  <td className="px-4 py-3 font-mono">{pr.amount} {pr.token || ''}</td>
                  <td className="px-4 py-3 capitalize">{pr.chain}</td>
                  <td className="px-4 py-3"><StatusBadge status={pr.status} /></td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(pr.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
              {payments.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                    No payment requests.
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
