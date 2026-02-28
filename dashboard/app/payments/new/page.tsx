'use client'

import { useState, type FormEvent } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'

const chains = ['ethereum', 'bitcoin', 'lux', 'solana', 'xrpl']

export default function NewPaymentPage() {
  const [merchantName, setMerchantName] = useState('')
  const [recipientAddress, setRecipientAddress] = useState('')
  const [chain, setChain] = useState('ethereum')
  const [amount, setAmount] = useState('')
  const [memo, setMemo] = useState('')
  const [expiresInHours, setExpiresInHours] = useState(24)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const [paymentUrl, setPaymentUrl] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      const result = await api.createPaymentRequest({
        merchant_name: merchantName || undefined,
        recipient_address: recipientAddress,
        chain,
        amount,
        memo: memo || undefined,
        expires_in_hours: expiresInHours,
      })
      setPaymentUrl(result.payment_url)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create payment request')
    } finally {
      setSubmitting(false)
    }
  }

  function handleCopy() {
    if (paymentUrl) {
      navigator.clipboard.writeText(paymentUrl)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  if (paymentUrl) {
    return (
      <>
        <Nav />
        <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-lg space-y-8">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">Payment Request Created</h1>
              <p className="mt-1 text-sm text-muted-foreground">Share this link with the payer.</p>
            </div>

            <div className="rounded-lg border border-border bg-card p-6 space-y-4">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-muted-foreground">Payment Link</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    readOnly
                    value={paymentUrl}
                    className="flex-1 rounded-md border border-input bg-background px-3 py-2 font-mono text-sm"
                  />
                  <button
                    onClick={handleCopy}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                  >
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <dt className="text-muted-foreground">Amount</dt>
                  <dd className="mt-1 font-mono">{amount}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Chain</dt>
                  <dd className="mt-1 capitalize">{chain}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Expires</dt>
                  <dd className="mt-1">{expiresInHours}h</dd>
                </div>
                {merchantName && (
                  <div>
                    <dt className="text-muted-foreground">Merchant</dt>
                    <dd className="mt-1">{merchantName}</dd>
                  </div>
                )}
              </dl>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => {
                  setPaymentUrl(null)
                  setMerchantName('')
                  setRecipientAddress('')
                  setAmount('')
                  setMemo('')
                }}
                className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground hover:bg-accent"
              >
                Create Another
              </button>
              <Link
                href="/payments"
                className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground hover:bg-accent"
              >
                Back to Payments
              </Link>
            </div>
          </div>
        </main>
      </>
    )
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/payments" className="hover:text-foreground">Payments</Link>
          <span>/</span>
          <span>New</span>
        </div>

        <h1 className="mb-8 text-2xl font-semibold tracking-tight">Create Payment Request</h1>

        <div className="mx-auto max-w-lg">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Merchant Name</label>
              <input
                type="text"
                value={merchantName}
                onChange={(e) => setMerchantName(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Your business name"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Recipient Address</label>
              <input
                type="text"
                required
                value={recipientAddress}
                onChange={(e) => setRecipientAddress(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="0x..."
              />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-muted-foreground">Chain</label>
                <select
                  value={chain}
                  onChange={(e) => setChain(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  {chains.map((c) => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-sm font-medium text-muted-foreground">Amount</label>
                <input
                  type="text"
                  required
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="100.00"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Memo</label>
              <textarea
                value={memo}
                onChange={(e) => setMemo(e.target.value)}
                rows={2}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Optional note for the payer"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Expiry (hours)</label>
              <input
                type="number"
                min={1}
                max={720}
                value={expiresInHours}
                onChange={(e) => setExpiresInHours(Number(e.target.value))}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>

            {error && <p className="text-sm text-destructive">{error}</p>}

            <button
              type="submit"
              disabled={submitting || !recipientAddress || !amount}
              className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {submitting ? 'Creating...' : 'Create Payment Request'}
            </button>
          </form>
        </div>
      </main>
    </>
  )
}
