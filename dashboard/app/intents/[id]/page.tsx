'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Intent } from '@/lib/types'

const intentSteps = ['pending_sign', 'signed', 'co_signed', 'recorded', 'matched', 'settling', 'settled', 'verified']

export default function IntentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [intent, setIntent] = useState<Intent | null>(null)
  const [error, setError] = useState('')
  const [acting, setActing] = useState(false)
  const [signature, setSignature] = useState('')
  const [keyId, setKeyId] = useState('')

  useEffect(() => {
    if (!id) return
    api.getIntent(id).then(setIntent).catch((e) => setError(e.message))
  }, [id])

  async function handleSign() {
    if (!signature.trim()) return
    setActing(true)
    setError('')
    try {
      const updated = await api.signIntent(id, { signature })
      setIntent(updated)
      setSignature('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Signing failed')
    } finally {
      setActing(false)
    }
  }

  async function handleCoSign() {
    if (!keyId.trim()) return
    setActing(true)
    setError('')
    try {
      const updated = await api.coSignIntent(id, { key_id: keyId })
      setIntent(updated)
      setKeyId('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Co-signing failed')
    } finally {
      setActing(false)
    }
  }

  const currentStep = intent ? intentSteps.indexOf(intent.status) : -1

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/intents" className="hover:text-foreground">Intents</Link>
          <span>/</span>
          <span className="font-mono">{id?.slice(0, 8)}...</span>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}
        {!intent && !error && <p className="text-sm text-muted-foreground">Loading...</p>}

        {intent && (
          <>
            <div className="mb-8 flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-semibold tracking-tight capitalize">{intent.intent_type} Intent</h1>
                <p className="mt-1 font-mono text-xs text-muted-foreground">{intent.id}</p>
              </div>
              <StatusBadge status={intent.status} />
            </div>

            {/* Lifecycle Progress */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Lifecycle</h2>
              <div className="flex items-center gap-1 overflow-x-auto">
                {intentSteps.map((step, i) => {
                  const isActive = i <= currentStep
                  const isCurrent = step === intent.status
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

            {/* Intent Details */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Details</h2>
              <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
                <div>
                  <dt className="text-muted-foreground">Type</dt>
                  <dd className="mt-1 capitalize">{intent.intent_type}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Chain</dt>
                  <dd className="mt-1 capitalize">{intent.chain}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Amount</dt>
                  <dd className="mt-1 font-mono">{intent.amount}</dd>
                </div>
                {intent.token && (
                  <div>
                    <dt className="text-muted-foreground">Token</dt>
                    <dd className="mt-1 font-mono text-xs">{intent.token}</dd>
                  </div>
                )}
                {intent.to_address && (
                  <div className="col-span-2">
                    <dt className="text-muted-foreground">To Address</dt>
                    <dd className="mt-1 font-mono text-xs break-all">{intent.to_address}</dd>
                  </div>
                )}
                <div>
                  <dt className="text-muted-foreground">Wallet</dt>
                  <dd className="mt-1">
                    <Link href={`/wallets/${intent.wallet_id}`} className="font-mono text-xs hover:underline">
                      {intent.wallet_id.slice(0, 12)}...
                    </Link>
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Created</dt>
                  <dd className="mt-1">{new Date(intent.created_at).toLocaleString()}</dd>
                </div>
                {intent.expires_at && (
                  <div>
                    <dt className="text-muted-foreground">Expires</dt>
                    <dd className="mt-1">{new Date(intent.expires_at).toLocaleString()}</dd>
                  </div>
                )}
              </dl>
            </div>

            {/* Intent Hash */}
            <div className="mb-8 rounded-lg border border-border bg-card p-6">
              <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Intent Hash</h2>
              <p className="font-mono text-xs break-all">{intent.intent_hash}</p>
            </div>

            {/* Signatures */}
            {(intent.signature || intent.co_signature) && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Signatures</h2>
                <dl className="space-y-3 text-sm">
                  {intent.signature && (
                    <div>
                      <dt className="text-muted-foreground">User Signature</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{intent.signature}</dd>
                    </div>
                  )}
                  {intent.co_signature && (
                    <div>
                      <dt className="text-muted-foreground">HSM Co-Signature</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{intent.co_signature}</dd>
                    </div>
                  )}
                  {intent.co_signer_key_id && (
                    <div>
                      <dt className="text-muted-foreground">Co-Signer Key ID</dt>
                      <dd className="mt-1 font-mono text-xs">{intent.co_signer_key_id}</dd>
                    </div>
                  )}
                </dl>
              </div>
            )}

            {/* On-chain Recording */}
            {(intent.on_chain_tx_hash || intent.recorded_at) && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">On-Chain Record</h2>
                <dl className="grid grid-cols-2 gap-4 text-sm">
                  {intent.on_chain_tx_hash && (
                    <div className="col-span-2">
                      <dt className="text-muted-foreground">TX Hash</dt>
                      <dd className="mt-1 font-mono text-xs break-all">{intent.on_chain_tx_hash}</dd>
                    </div>
                  )}
                  {intent.recorded_at && (
                    <div>
                      <dt className="text-muted-foreground">Recorded At</dt>
                      <dd className="mt-1">{new Date(intent.recorded_at).toLocaleString()}</dd>
                    </div>
                  )}
                  {intent.recorded_block != null && (
                    <div>
                      <dt className="text-muted-foreground">Block</dt>
                      <dd className="mt-1 font-mono">{intent.recorded_block}</dd>
                    </div>
                  )}
                </dl>
              </div>
            )}

            {/* Matching */}
            {(intent.match_id || intent.matched_at) && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Match</h2>
                <dl className="grid grid-cols-2 gap-4 text-sm">
                  {intent.match_id && (
                    <div>
                      <dt className="text-muted-foreground">Match ID</dt>
                      <dd className="mt-1 font-mono text-xs">{intent.match_id}</dd>
                    </div>
                  )}
                  {intent.matched_at && (
                    <div>
                      <dt className="text-muted-foreground">Matched At</dt>
                      <dd className="mt-1">{new Date(intent.matched_at).toLocaleString()}</dd>
                    </div>
                  )}
                </dl>
              </div>
            )}

            {/* Status History */}
            {intent.status_history && intent.status_history.length > 0 && (
              <div className="mb-8 rounded-lg border border-border bg-card p-6">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-wider text-muted-foreground">Status History</h2>
                <div className="space-y-3">
                  {intent.status_history.map((t, i) => (
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

            {/* Actions */}
            {intent.status === 'pending_sign' && (
              <div className="rounded-lg border border-border bg-card p-6 space-y-4">
                <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Sign Intent</h2>
                <div className="flex items-end gap-3">
                  <div className="flex-1">
                    <label className="mb-1.5 block text-xs text-muted-foreground">Signature (hex)</label>
                    <input
                      type="text"
                      value={signature}
                      onChange={(e) => setSignature(e.target.value)}
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="0x..."
                    />
                  </div>
                  <button
                    onClick={handleSign}
                    disabled={acting || !signature.trim()}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {acting ? 'Signing...' : 'Sign'}
                  </button>
                </div>
              </div>
            )}

            {intent.status === 'signed' && (
              <div className="rounded-lg border border-border bg-card p-6 space-y-4">
                <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">HSM Co-Sign</h2>
                <p className="text-xs text-muted-foreground">
                  The server will sign directly with the HSM. Provide the key ID to use.
                </p>
                <div className="flex items-end gap-3">
                  <div className="flex-1">
                    <label className="mb-1.5 block text-xs text-muted-foreground">HSM Key ID</label>
                    <input
                      type="text"
                      value={keyId}
                      onChange={(e) => setKeyId(e.target.value)}
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="aws-kms://key-id or gcp-kms://..."
                    />
                  </div>
                  <button
                    onClick={handleCoSign}
                    disabled={acting || !keyId.trim()}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {acting ? 'Co-signing...' : 'Co-Sign with HSM'}
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </>
  )
}
