'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Subscription } from '@/lib/types'

export default function SubscriptionsPage() {
  const router = useRouter()
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    api.listSubscriptions().then(setSubscriptions).catch((e) => setError(e.message))
  }, [])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Subscriptions</h1>
            <p className="mt-1 text-sm text-muted-foreground">Manage recurring payments.</p>
          </div>
          <Link
            href="/subscriptions/new"
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Create Subscription
          </Link>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Name</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Recipient</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Amount</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Interval</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Next Payment</th>
              </tr>
            </thead>
            <tbody>
              {subscriptions.map((sub) => (
                <tr
                  key={sub.id}
                  onClick={() => router.push(`/subscriptions/${sub.id}`)}
                  className="cursor-pointer border-b border-border last:border-0 hover:bg-muted/30"
                >
                  <td className="px-4 py-3 font-medium">{sub.name}</td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {sub.recipient_address.slice(0, 10)}...{sub.recipient_address.slice(-6)}
                  </td>
                  <td className="px-4 py-3 font-mono">
                    {sub.amount} {sub.token || sub.currency}
                  </td>
                  <td className="px-4 py-3 capitalize">{sub.interval}</td>
                  <td className="px-4 py-3"><StatusBadge status={sub.status} /></td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(sub.next_payment_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
              {subscriptions.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    No subscriptions.
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
