'use client'

import { useState, type FormEvent } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'

const chains = [
  { value: 'ethereum', label: 'Ethereum' },
  { value: 'bitcoin', label: 'Bitcoin' },
  { value: 'lux', label: 'Lux' },
  { value: 'solana', label: 'Solana' },
  { value: 'xrpl', label: 'XRPL' },
]

const txTypes = [
  { value: 'transfer', label: 'Transfer' },
  { value: 'contract_call', label: 'Contract Call' },
]

export default function SendPage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()

  const [chain, setChain] = useState('ethereum')
  const [toAddress, setToAddress] = useState('')
  const [amount, setAmount] = useState('')
  const [token, setToken] = useState('')
  const [txType, setTxType] = useState('transfer')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPreview, setShowPreview] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()

    if (!showPreview) {
      setShowPreview(true)
      return
    }

    setLoading(true)
    setError('')
    try {
      const tx = await api.createTransaction({
        wallet_id: id,
        tx_type: txType,
        chain,
        to_address: toAddress,
        amount,
        token: token || undefined,
      })
      router.push(`/transactions/${tx.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Transaction failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href={`/wallets/${id}`} className="hover:text-foreground">Wallet</Link>
          <span>/</span>
          <span>Send</span>
        </div>

        <h1 className="mb-8 text-2xl font-semibold tracking-tight">Send Transaction</h1>

        <div className="mx-auto max-w-lg">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">Chain</label>
              <select
                value={chain}
                onChange={(e) => setChain(e.target.value)}
                disabled={showPreview}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {chains.map((c) => (
                  <option key={c.value} value={c.value}>{c.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">Transaction Type</label>
              <select
                value={txType}
                onChange={(e) => setTxType(e.target.value)}
                disabled={showPreview}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {txTypes.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">To Address</label>
              <input
                type="text"
                required
                value={toAddress}
                onChange={(e) => setToAddress(e.target.value)}
                disabled={showPreview}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="0x..."
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">Amount</label>
              <input
                type="text"
                required
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                disabled={showPreview}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="0.0"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">Token (optional)</label>
              <input
                type="text"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                disabled={showPreview}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Contract address or leave blank for native"
              />
            </div>

            {showPreview && (
              <div className="rounded-lg border border-border bg-muted/50 p-4 space-y-2">
                <h3 className="text-sm font-medium">Preview</h3>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <span className="text-muted-foreground">Chain</span>
                  <span className="capitalize">{chain}</span>
                  <span className="text-muted-foreground">Type</span>
                  <span className="capitalize">{txType.replace('_', ' ')}</span>
                  <span className="text-muted-foreground">To</span>
                  <span className="font-mono text-xs break-all">{toAddress}</span>
                  <span className="text-muted-foreground">Amount</span>
                  <span className="font-mono">{amount}</span>
                  {token && (
                    <>
                      <span className="text-muted-foreground">Token</span>
                      <span className="font-mono text-xs break-all">{token}</span>
                    </>
                  )}
                </div>
              </div>
            )}

            {error && <p className="text-sm text-destructive">{error}</p>}

            <div className="flex justify-between pt-2">
              {showPreview ? (
                <>
                  <button
                    type="button"
                    onClick={() => setShowPreview(false)}
                    className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent"
                  >
                    Edit
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
                  >
                    {loading ? 'Submitting...' : 'Confirm & Send'}
                  </button>
                </>
              ) : (
                <button
                  type="submit"
                  className="ml-auto rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                >
                  Preview
                </button>
              )}
            </div>
          </form>
        </div>
      </main>
    </>
  )
}
