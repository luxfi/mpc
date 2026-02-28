'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Transaction } from '@/lib/types'

export default function TransactionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [tx, setTx] = useState<Transaction | null>(null)
  const [error, setError] = useState('')
  const [acting, setActing] = useState(false)
  const [rejectReason, setRejectReason] = useState('')

  useEffect(() => {
    if (!id) return
    api.getTransaction(id).then(setTx).catch((e) => setError(e.message))
  }, [id])

  async function handleApprove() {
    setActing(true)
    setError('')
    try {
      await api.approveTransaction(id)
      const updated = await api.getTransaction(id)
      setTx(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Approval failed')
    } finally {
      setActing(false)
    }
  }

  async function handleReject() {
    setActing(true)
    setError('')
    try {
      await api.rejectTransaction(id, { reason: rejectReason || undefined })
      const updated = await api.getTransaction(id)
      setTx(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Rejection failed')
    } finally {
      setActing(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/transactions" className="hover:text-foreground">Transactions</Link>
          <span>/</span>
          <span className="font-mono">{id?.slice(0, 8)}...</span>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}
        {!tx && !error && <p className="text-sm text-muted-foreground">Loading...</p>}

        {tx && (
          <>
            <div className="mb-8 flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold tracking-tight capitalize">{tx.tx_type} Transaction</h1>
                <p className="mt-1 font-mono text-xs text-muted-foreground">{tx.id}</p>
              </div>
              <StatusBadge status={tx.status} />
            </div>

            {/* Transaction Info */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Details</h2>
              <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
                <div>
                  <dt className="text-muted-foreground">Type</dt>
                  <dd className="mt-1 capitalize">{tx.tx_type}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Chain</dt>
                  <dd className="mt-1 capitalize">{tx.chain}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Amount</dt>
                  <dd className="mt-1 font-mono">{tx.amount || '--'}</dd>
                </div>
                {tx.token && (
                  <div>
                    <dt className="text-muted-foreground">Token</dt>
                    <dd className="mt-1 font-mono text-xs">{tx.token}</dd>
                  </div>
                )}
                <div className="col-span-2">
                  <dt className="text-muted-foreground">To Address</dt>
                  <dd className="mt-1 font-mono text-xs break-all">{tx.to_address || '--'}</dd>
                </div>
                {tx.wallet_id && (
                  <div>
                    <dt className="text-muted-foreground">Wallet</dt>
                    <dd className="mt-1">
                      <Link href={`/wallets/${tx.wallet_id}`} className="font-mono text-xs hover:underline">
                        {tx.wallet_id.slice(0, 12)}...
                      </Link>
                    </dd>
                  </div>
                )}
                {tx.initiated_by && (
                  <div>
                    <dt className="text-muted-foreground">Initiated By</dt>
                    <dd className="mt-1 font-mono text-xs">{tx.initiated_by}</dd>
                  </div>
                )}
                <div>
                  <dt className="text-muted-foreground">Created</dt>
                  <dd className="mt-1">{new Date(tx.created_at).toLocaleString()}</dd>
                </div>
                {tx.signed_at && (
                  <div>
                    <dt className="text-muted-foreground">Signed</dt>
                    <dd className="mt-1">{new Date(tx.signed_at).toLocaleString()}</dd>
                  </div>
                )}
                {tx.broadcast_at && (
                  <div>
                    <dt className="text-muted-foreground">Broadcast</dt>
                    <dd className="mt-1">{new Date(tx.broadcast_at).toLocaleString()}</dd>
                  </div>
                )}
              </dl>
            </div>

            {/* TX Hash */}
            {tx.tx_hash && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Transaction Hash</h2>
                <p className="font-mono text-xs break-all">{tx.tx_hash}</p>
              </div>
            )}

            {/* Signature */}
            {(tx.signature_r || tx.signature_s || tx.signature_eddsa) && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Signature</h2>
                <dl className="space-y-3 text-sm">
                  {tx.signature_r && (
                    <div>
                      <dt className="text-muted-foreground">R</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{tx.signature_r}</dd>
                    </div>
                  )}
                  {tx.signature_s && (
                    <div>
                      <dt className="text-muted-foreground">S</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{tx.signature_s}</dd>
                    </div>
                  )}
                  {tx.signature_eddsa && (
                    <div>
                      <dt className="text-muted-foreground">EdDSA</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{tx.signature_eddsa}</dd>
                    </div>
                  )}
                </dl>
              </div>
            )}

            {/* Approvals / Rejection */}
            {tx.approved_by && tx.approved_by.length > 0 && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Approved By</h2>
                <div className="flex flex-wrap gap-2">
                  {tx.approved_by.map((u) => (
                    <span key={u} className="rounded-md border border-border bg-muted/50 px-2 py-1 font-mono text-xs">{u}</span>
                  ))}
                </div>
              </div>
            )}

            {tx.rejected_by && (
              <div className="mb-8 rounded-lg border border-destructive/30 bg-destructive/5 p-6">
                <h2 className="mb-2 text-sm font-medium text-destructive">Rejected</h2>
                <p className="text-sm">By: <span className="font-mono text-xs">{tx.rejected_by}</span></p>
                {tx.rejection_reason && (
                  <p className="mt-1 text-sm text-muted-foreground">Reason: {tx.rejection_reason}</p>
                )}
              </div>
            )}

            {/* Actions */}
            {tx.status === 'pending_approval' && (
              <div className="rounded-lg border border-border bg-card p-6 space-y-4">
                <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Actions</h2>
                <div className="flex flex-wrap items-end gap-4">
                  <button
                    onClick={handleApprove}
                    disabled={acting}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {acting ? 'Processing...' : 'Approve'}
                  </button>
                  <div className="flex items-end gap-2">
                    <div>
                      <label className="mb-1.5 block text-xs text-muted-foreground">Reason (optional)</label>
                      <input
                        type="text"
                        value={rejectReason}
                        onChange={(e) => setRejectReason(e.target.value)}
                        className="rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                        placeholder="Rejection reason"
                      />
                    </div>
                    <button
                      onClick={handleReject}
                      disabled={acting}
                      className="rounded-md border border-destructive/30 px-4 py-2 text-sm font-medium text-destructive hover:bg-destructive/10 disabled:opacity-50"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </>
  )
}
