'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import { isWebAuthnSupported, startAuthentication } from '@/lib/webauthn'
import type { TransactionDetail as TxDetail } from '@/lib/types'

export default function TransactionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [tx, setTx] = useState<TxDetail | null>(null)
  const [error, setError] = useState('')
  const [acting, setActing] = useState(false)
  const [rejectReason, setRejectReason] = useState('')
  const [hasWebAuthn, setHasWebAuthn] = useState(false)

  useEffect(() => { setHasWebAuthn(isWebAuthnSupported()) }, [])

  useEffect(() => {
    if (!id) return
    api.getTransaction(id).then((t) => setTx(t as TxDetail)).catch((e) => setError(e.message))
  }, [id])

  async function handleApprove() {
    setActing(true)
    setError('')
    try {
      await api.approveTransaction(id)
      const updated = await api.getTransaction(id) as TxDetail
      setTx(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Approval failed')
    } finally {
      setActing(false)
    }
  }

  async function handleBiometricApprove() {
    setActing(true)
    setError('')
    try {
      const assertion = await startAuthentication(id)
      await api.webauthnVerify(id, assertion)
      const updated = await api.getTransaction(id) as TxDetail
      setTx(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Biometric approval failed')
    } finally {
      setActing(false)
    }
  }

  async function handleReject() {
    setActing(true)
    setError('')
    try {
      await api.rejectTransaction(id, { reason: rejectReason || undefined })
      const updated = await api.getTransaction(id) as TxDetail
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

            {/* On-Chain Confirmation */}
            {(tx.block_number != null || (tx.confirmations ?? 0) > 0 || tx.revert_reason) && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">On-Chain Status</h2>
                <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
                  {tx.block_number != null && (
                    <div>
                      <dt className="text-muted-foreground">Block Number</dt>
                      <dd className="mt-1 font-mono">{tx.block_number}</dd>
                    </div>
                  )}
                  {tx.block_hash && (
                    <div className="col-span-2">
                      <dt className="text-muted-foreground">Block Hash</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{tx.block_hash}</dd>
                    </div>
                  )}
                  <div>
                    <dt className="text-muted-foreground">Confirmations</dt>
                    <dd className="mt-1">
                      <span className="font-mono">{tx.confirmations ?? 0}</span>
                      <span className="text-muted-foreground"> / {tx.target_confirmations ?? 12}</span>
                      {(tx.confirmations ?? 0) >= (tx.target_confirmations ?? 12) && (
                        <span className="ml-2 text-xs text-emerald-400">Finalized</span>
                      )}
                    </dd>
                  </div>
                  {tx.gas_used && (
                    <div>
                      <dt className="text-muted-foreground">Gas Used</dt>
                      <dd className="mt-1 font-mono">{tx.gas_used}</dd>
                    </div>
                  )}
                  {tx.receipt_status != null && (
                    <div>
                      <dt className="text-muted-foreground">Receipt Status</dt>
                      <dd className="mt-1">
                        {tx.receipt_status === 1 ? (
                          <span className="text-emerald-400">Success</span>
                        ) : (
                          <span className="text-red-400">Reverted</span>
                        )}
                      </dd>
                    </div>
                  )}
                  {tx.nonce != null && (
                    <div>
                      <dt className="text-muted-foreground">Nonce</dt>
                      <dd className="mt-1 font-mono">{tx.nonce}</dd>
                    </div>
                  )}
                  {tx.finalized_at && (
                    <div>
                      <dt className="text-muted-foreground">Finalized At</dt>
                      <dd className="mt-1">{new Date(tx.finalized_at).toLocaleString()}</dd>
                    </div>
                  )}
                </dl>
                {tx.revert_reason && (
                  <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/5 p-3">
                    <p className="text-xs font-medium text-destructive">Revert Reason</p>
                    <p className="mt-1 font-mono text-xs text-destructive/80">{tx.revert_reason}</p>
                  </div>
                )}
              </div>
            )}

            {/* Settlement Link */}
            {(tx.intent_id || tx.settlement_tx_hash) && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Settlement</h2>
                <dl className="grid grid-cols-2 gap-4 text-sm">
                  {tx.intent_id && (
                    <div>
                      <dt className="text-muted-foreground">Intent</dt>
                      <dd className="mt-1">
                        <Link href={`/intents/${tx.intent_id}`} className="font-mono text-xs hover:underline">
                          {tx.intent_id.slice(0, 12)}...
                        </Link>
                      </dd>
                    </div>
                  )}
                  {tx.settlement_tx_hash && (
                    <div className="col-span-2">
                      <dt className="text-muted-foreground">Settlement TX Hash</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{tx.settlement_tx_hash}</dd>
                    </div>
                  )}
                  {tx.settled_at && (
                    <div>
                      <dt className="text-muted-foreground">Settled At</dt>
                      <dd className="mt-1">{new Date(tx.settled_at).toLocaleString()}</dd>
                    </div>
                  )}
                </dl>
              </div>
            )}

            {/* Status History */}
            {tx.status_history && tx.status_history.length > 0 && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Status History</h2>
                <div className="space-y-3">
                  {tx.status_history.map((t, i) => (
                    <div key={i} className="flex items-start gap-3 text-sm">
                      <div className="flex items-center gap-2">
                        <StatusBadge status={t.from || 'new'} />
                        <span className="text-muted-foreground">-&gt;</span>
                        <StatusBadge status={t.to} />
                      </div>
                      <span className="text-xs text-muted-foreground">{new Date(t.timestamp).toLocaleString()}</span>
                      {t.detail && <span className="text-xs text-muted-foreground">- {t.detail}</span>}
                      {t.actor && <span className="text-xs font-mono text-muted-foreground">({t.actor})</span>}
                    </div>
                  ))}
                </div>
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
                  {hasWebAuthn && (
                    <button
                      onClick={handleBiometricApprove}
                      disabled={acting}
                      className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                    >
                      {acting ? 'Processing...' : 'Approve with Biometrics'}
                    </button>
                  )}
                  <button
                    onClick={handleApprove}
                    disabled={acting}
                    className="rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent disabled:opacity-50"
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
