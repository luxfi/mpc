'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Subscription } from '@/lib/types'

export default function SubscriptionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [sub, setSub] = useState<Subscription | null>(null)
  const [error, setError] = useState('')
  const [acting, setActing] = useState(false)

  useEffect(() => {
    if (!id) return
    api.getSubscription(id).then(setSub).catch((e) => setError(e.message))
  }, [id])

  async function handlePayNow() {
    setActing(true)
    setError('')
    try {
      await api.payNow(id)
      const updated = await api.getSubscription(id)
      setSub(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Payment failed')
    } finally {
      setActing(false)
    }
  }

  async function handleStatusChange(status: string) {
    setActing(true)
    setError('')
    try {
      const updated = await api.updateSubscription(id, { status })
      setSub(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Update failed')
    } finally {
      setActing(false)
    }
  }

  async function handleCancel() {
    setActing(true)
    setError('')
    try {
      await api.deleteSubscription(id)
      const updated = await api.getSubscription(id)
      setSub(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Cancellation failed')
    } finally {
      setActing(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/subscriptions" className="hover:text-foreground">Subscriptions</Link>
          <span>/</span>
          <span>{sub?.name || 'Detail'}</span>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}
        {!sub && !error && <p className="text-sm text-muted-foreground">Loading...</p>}

        {sub && (
          <>
            <div className="mb-8 flex items-start justify-between">
              <div>
                <h1 className="text-2xl font-semibold tracking-tight">{sub.name}</h1>
                {sub.provider_name && (
                  <p className="mt-1 text-sm text-muted-foreground">{sub.provider_name}</p>
                )}
              </div>
              <StatusBadge status={sub.status} />
            </div>

            {/* Info */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">
                Subscription Details
              </h2>
              <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
                <div>
                  <dt className="text-muted-foreground">Amount</dt>
                  <dd className="mt-1 font-mono">{sub.amount} {sub.token || sub.currency}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Interval</dt>
                  <dd className="mt-1 capitalize">{sub.interval}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Chain</dt>
                  <dd className="mt-1 capitalize">{sub.chain}</dd>
                </div>
                {sub.wallet_id && (
                  <div>
                    <dt className="text-muted-foreground">Wallet</dt>
                    <dd className="mt-1">
                      <Link href={`/wallets/${sub.wallet_id}`} className="font-mono text-xs hover:underline">
                        {sub.wallet_id.slice(0, 12)}...
                      </Link>
                    </dd>
                  </div>
                )}
                <div className="col-span-2">
                  <dt className="text-muted-foreground">Recipient</dt>
                  <dd className="mt-1 font-mono text-xs break-all">{sub.recipient_address}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Next Payment</dt>
                  <dd className="mt-1">{new Date(sub.next_payment_at).toLocaleDateString()}</dd>
                </div>
                {sub.last_payment_at && (
                  <div>
                    <dt className="text-muted-foreground">Last Payment</dt>
                    <dd className="mt-1">{new Date(sub.last_payment_at).toLocaleDateString()}</dd>
                  </div>
                )}
                <div>
                  <dt className="text-muted-foreground">Created</dt>
                  <dd className="mt-1">{new Date(sub.created_at).toLocaleDateString()}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Require Balance</dt>
                  <dd className="mt-1">{sub.require_balance ? 'Yes' : 'No'}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Retries</dt>
                  <dd className="mt-1">{sub.retry_count} / {sub.max_retries}</dd>
                </div>
              </dl>
            </div>

            {/* Actions */}
            <div className="flex flex-wrap gap-3">
              {sub.status === 'active' && (
                <>
                  <button
                    onClick={handlePayNow}
                    disabled={acting}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {acting ? 'Processing...' : 'Pay Now'}
                  </button>
                  <button
                    onClick={() => handleStatusChange('paused')}
                    disabled={acting}
                    className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground hover:bg-accent disabled:opacity-50"
                  >
                    Pause
                  </button>
                </>
              )}
              {sub.status === 'paused' && (
                <button
                  onClick={() => handleStatusChange('active')}
                  disabled={acting}
                  className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                >
                  Resume
                </button>
              )}
              {sub.status !== 'cancelled' && (
                <button
                  onClick={handleCancel}
                  disabled={acting}
                  className="rounded-md border border-destructive/30 px-4 py-2 text-sm font-medium text-destructive hover:bg-destructive/10 disabled:opacity-50"
                >
                  Cancel Subscription
                </button>
              )}
            </div>
          </>
        )}
      </main>
    </>
  )
}
