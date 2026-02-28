'use client'

import { useState, useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { api, APIError } from '@/lib/api'
import { ReshareWizard } from '@/components/wallets/reshare-wizard'
import type { Wallet } from '@/lib/types'

type ReshareStatus = 'idle' | 'confirming' | 'running' | 'success' | 'error'

export default function ResharePage() {
  const params = useParams<{ id: string }>()
  const router = useRouter()

  const [wallet, setWallet] = useState<Wallet | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState('')

  const [newThreshold, setNewThreshold] = useState(2)
  const [newParticipants, setNewParticipants] = useState('')
  const [status, setStatus] = useState<ReshareStatus>('idle')
  const [error, setError] = useState('')

  useEffect(() => {
    async function fetchWallet() {
      try {
        const w = await api.getWallet(params.id)
        setWallet(w)
        setNewThreshold(w.threshold)
        setNewParticipants(w.participants.join('\n'))
      } catch (err) {
        setFetchError(err instanceof APIError ? err.message : 'Failed to load wallet')
      } finally {
        setLoading(false)
      }
    }
    fetchWallet()
  }, [params.id])

  const participantList = newParticipants
    .split('\n')
    .map((p) => p.trim())
    .filter(Boolean)

  async function handleConfirm() {
    setStatus('confirming')
  }

  async function handleReshare() {
    setStatus('running')
    setError('')
    try {
      await api.reshareWallet(params.id, {
        new_threshold: newThreshold,
        new_participants: participantList,
      })
      setStatus('success')
    } catch (err) {
      setError(err instanceof APIError ? err.message : 'Reshare failed')
      setStatus('error')
    }
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <p className="text-sm text-muted-foreground">Loading wallet...</p>
      </div>
    )
  }

  if (fetchError || !wallet) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8">
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {fetchError || 'Wallet not found'}
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8 px-4 py-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Reshare Key Shares
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Rotate key shares for wallet{' '}
          <span className="font-mono">{wallet.name ?? wallet.id}</span> without changing the
          public key or on-chain addresses.
        </p>
      </div>

      {/* Current wallet info */}
      <section className="rounded-lg border border-border bg-card p-6 space-y-4">
        <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
          Current Configuration
        </h2>
        <dl className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <dt className="text-muted-foreground">Threshold</dt>
            <dd className="mt-1 font-mono">
              {wallet.threshold}-of-{wallet.participants.length}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Participants</dt>
            <dd className="mt-1 font-mono">
              {wallet.participants.length} nodes
            </dd>
          </div>
          <div className="col-span-2">
            <dt className="text-muted-foreground">ECDSA Public Key</dt>
            <dd className="mt-1 truncate font-mono text-xs">
              {wallet.ecdsa_pubkey ?? 'N/A'}
            </dd>
          </div>
        </dl>
      </section>

      {/* Warning */}
      <div className="rounded-lg border border-yellow-600/30 bg-yellow-600/10 p-4 text-sm">
        <p className="font-medium text-yellow-500">Key Rotation Warning</p>
        <p className="mt-1 text-yellow-500/80">
          Resharing invalidates all existing key shares. All participants must be
          online and reachable during the process. Ensure backups exist before
          proceeding.
        </p>
      </div>

      {status === 'idle' && (
        <section className="space-y-6">
          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="threshold">
              New Threshold
            </label>
            <input
              id="threshold"
              type="number"
              min={1}
              max={participantList.length}
              value={newThreshold}
              onChange={(e) => setNewThreshold(Number(e.target.value))}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <p className="text-xs text-muted-foreground">
              Minimum signers required (1 to {participantList.length})
            </p>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="participants">
              New Participants (one per line)
            </label>
            <textarea
              id="participants"
              rows={5}
              value={newParticipants}
              onChange={(e) => setNewParticipants(e.target.value)}
              className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <p className="text-xs text-muted-foreground">
              {participantList.length} participant
              {participantList.length !== 1 ? 's' : ''} configured
            </p>
          </div>

          <button
            onClick={handleConfirm}
            disabled={participantList.length < 1 || newThreshold < 1}
            className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            Review Reshare
          </button>
        </section>
      )}

      {status === 'confirming' && (
        <section className="space-y-6">
          <div className="rounded-lg border border-border bg-card p-6 space-y-3 text-sm">
            <h2 className="font-medium">Confirm Reshare</h2>
            <p>
              <span className="text-muted-foreground">New threshold:</span>{' '}
              <span className="font-mono">
                {newThreshold}-of-{participantList.length}
              </span>
            </p>
            <p className="text-muted-foreground">New participants:</p>
            <ul className="list-inside list-disc font-mono text-xs space-y-1">
              {participantList.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setStatus('idle')}
              className="flex-1 rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent"
            >
              Back
            </button>
            <button
              onClick={handleReshare}
              className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Confirm Reshare
            </button>
          </div>
        </section>
      )}

      {status === 'running' && (
        <ReshareWizard
          step="resharing"
          threshold={newThreshold}
          participants={participantList}
        />
      )}

      {status === 'success' && (
        <section className="rounded-lg border border-green-600/30 bg-green-600/10 p-6 text-center space-y-4">
          <p className="text-lg font-medium text-green-500">
            Reshare Complete
          </p>
          <p className="text-sm text-green-500/80">
            Key shares have been rotated. New threshold:{' '}
            <span className="font-mono">
              {newThreshold}-of-{participantList.length}
            </span>
          </p>
          <button
            onClick={() => router.push(`/wallets/${params.id}`)}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            Back to Wallet
          </button>
        </section>
      )}

      {status === 'error' && (
        <section className="rounded-lg border border-destructive/30 bg-destructive/10 p-6 text-center space-y-4">
          <p className="text-lg font-medium text-destructive">
            Reshare Failed
          </p>
          <p className="text-sm text-destructive/80">{error}</p>
          <button
            onClick={() => setStatus('idle')}
            className="rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent"
          >
            Try Again
          </button>
        </section>
      )}
    </div>
  )
}
