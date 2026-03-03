'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Settlement } from '@/lib/types'

const settlementSteps = ['pending', 'hsm_signing', 'broadcast', 'confirming', 'finalized', 'verified']

export default function SettlementDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [settlement, setSettlement] = useState<Settlement | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) return
    api.getSettlement(id).then(setSettlement).catch((e) => setError(e.message))
  }, [id])

  const currentStep = settlement ? settlementSteps.indexOf(settlement.status) : -1

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/settlements" className="hover:text-foreground">Settlements</Link>
          <span>/</span>
          <span className="font-mono">{id?.slice(0, 8)}...</span>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}
        {!settlement && !error && <p className="text-sm text-muted-foreground">Loading...</p>}

        {settlement && (
          <>
            <div className="mb-8 flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold tracking-tight">Settlement</h1>
                <p className="mt-1 font-mono text-xs text-muted-foreground">{settlement.id}</p>
              </div>
              <StatusBadge status={settlement.status} />
            </div>

            {/* Lifecycle Progress */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Lifecycle</h2>
              <div className="flex items-center gap-1 overflow-x-auto">
                {settlementSteps.map((step, i) => {
                  const isActive = i <= currentStep
                  const isCurrent = step === settlement.status
                  return (
                    <div key={step} className="flex items-center gap-1">
                      {i > 0 && (
                        <div className={`h-0.5 w-6 ${isActive ? 'bg-emerald-500' : 'bg-border'}`} />
                      )}
                      <div
                        className={`whitespace-nowrap rounded-md px-2.5 py-1.5 text-xs font-medium capitalize ${
                          isCurrent
                            ? 'bg-primary text-primary-foreground'
                            : isActive
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-muted text-muted-foreground'
                        }`}
                      >
                        {step.replace(/_/g, ' ')}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Settlement Details */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Details</h2>
              <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
                <div>
                  <dt className="text-muted-foreground">Intent</dt>
                  <dd className="mt-1">
                    <Link href={`/intents/${settlement.intent_id}`} className="font-mono text-xs hover:underline">
                      {settlement.intent_id.slice(0, 12)}...
                    </Link>
                  </dd>
                </div>
                {settlement.match_id && (
                  <div>
                    <dt className="text-muted-foreground">Match ID</dt>
                    <dd className="mt-1 font-mono text-xs">{settlement.match_id}</dd>
                  </div>
                )}
                <div>
                  <dt className="text-muted-foreground">Created</dt>
                  <dd className="mt-1">{new Date(settlement.created_at).toLocaleString()}</dd>
                </div>
                {settlement.matched_at && (
                  <div>
                    <dt className="text-muted-foreground">Matched</dt>
                    <dd className="mt-1">{new Date(settlement.matched_at).toLocaleString()}</dd>
                  </div>
                )}
                {settlement.signed_at && (
                  <div>
                    <dt className="text-muted-foreground">Signed</dt>
                    <dd className="mt-1">{new Date(settlement.signed_at).toLocaleString()}</dd>
                  </div>
                )}
                {settlement.broadcast_at && (
                  <div>
                    <dt className="text-muted-foreground">Broadcast</dt>
                    <dd className="mt-1">{new Date(settlement.broadcast_at).toLocaleString()}</dd>
                  </div>
                )}
                {settlement.finalized_at && (
                  <div>
                    <dt className="text-muted-foreground">Finalized</dt>
                    <dd className="mt-1">{new Date(settlement.finalized_at).toLocaleString()}</dd>
                  </div>
                )}
                {settlement.verified_at && (
                  <div>
                    <dt className="text-muted-foreground">Verified</dt>
                    <dd className="mt-1">{new Date(settlement.verified_at).toLocaleString()}</dd>
                  </div>
                )}
              </dl>
            </div>

            {/* Transaction Hashes */}
            {(settlement.settlement_tx_hash || settlement.finalize_tx_hash) && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Transaction Hashes</h2>
                <dl className="space-y-3 text-sm">
                  {settlement.settlement_tx_hash && (
                    <div>
                      <dt className="text-muted-foreground">Settlement TX</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{settlement.settlement_tx_hash}</dd>
                    </div>
                  )}
                  {settlement.finalize_tx_hash && (
                    <div>
                      <dt className="text-muted-foreground">Finalize TX</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{settlement.finalize_tx_hash}</dd>
                    </div>
                  )}
                  {settlement.finalized_block_number != null && (
                    <div>
                      <dt className="text-muted-foreground">Finalized Block</dt>
                      <dd className="mt-1 font-mono">{settlement.finalized_block_number}</dd>
                    </div>
                  )}
                </dl>
              </div>
            )}

            {/* HSM Signatures */}
            {settlement.hsm_signatures && settlement.hsm_signatures.length > 0 && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">
                  HSM Signatures ({settlement.hsm_signatures.length})
                </h2>
                <div className="space-y-4">
                  {settlement.hsm_signatures.map((sig, i) => (
                    <div key={i} className="rounded-md border border-border bg-muted/30 p-4">
                      <dl className="grid grid-cols-2 gap-3 text-sm">
                        <div>
                          <dt className="text-muted-foreground">Provider</dt>
                          <dd className="mt-0.5 capitalize">{sig.provider}</dd>
                        </div>
                        <div>
                          <dt className="text-muted-foreground">Signer</dt>
                          <dd className="mt-0.5 font-mono text-xs">{sig.signer_id}</dd>
                        </div>
                        <div>
                          <dt className="text-muted-foreground">Key ID</dt>
                          <dd className="mt-0.5 font-mono text-xs">{sig.key_id}</dd>
                        </div>
                        <div>
                          <dt className="text-muted-foreground">Signed At</dt>
                          <dd className="mt-0.5">{new Date(sig.signed_at).toLocaleString()}</dd>
                        </div>
                        <div className="col-span-2">
                          <dt className="text-muted-foreground">Signature</dt>
                          <dd className="mt-0.5 font-mono text-xs break-all">{sig.signature}</dd>
                        </div>
                      </dl>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Transfer Agency Verification */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Transfer Agency</h2>
              <dl className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">Verified</dt>
                  <dd className="mt-1">
                    {settlement.transfer_agency_verified ? (
                      <span className="font-medium text-emerald-400">Verified</span>
                    ) : (
                      <span className="text-muted-foreground">Pending</span>
                    )}
                  </dd>
                </div>
                {settlement.transfer_agency_verified_at && (
                  <div>
                    <dt className="text-muted-foreground">Verified At</dt>
                    <dd className="mt-1">{new Date(settlement.transfer_agency_verified_at).toLocaleString()}</dd>
                  </div>
                )}
                {settlement.transfer_agency_hash && (
                  <div className="col-span-2">
                    <dt className="text-muted-foreground">Transfer Hash</dt>
                    <dd className="mt-1 font-mono text-xs break-all">{settlement.transfer_agency_hash}</dd>
                  </div>
                )}
              </dl>
            </div>

            {/* Status History */}
            {settlement.status_history && settlement.status_history.length > 0 && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Status History</h2>
                <div className="space-y-3">
                  {settlement.status_history.map((t, i) => (
                    <div key={i} className="flex items-start gap-3 text-sm">
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <StatusBadge status={t.from || 'new'} />
                        <span>-&gt;</span>
                        <StatusBadge status={t.to} />
                      </div>
                      <span className="text-xs text-muted-foreground">{new Date(t.timestamp).toLocaleString()}</span>
                      {t.detail && <span className="text-xs text-muted-foreground">- {t.detail}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </>
  )
}
