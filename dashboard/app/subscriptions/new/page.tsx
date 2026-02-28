'use client'

import { useState, useEffect, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { Wallet, Vault } from '@/lib/types'

const chains = ['ethereum', 'bitcoin', 'lux', 'solana', 'xrpl']
const intervals = ['daily', 'weekly', 'monthly', 'yearly']

export default function NewSubscriptionPage() {
  const router = useRouter()

  const [wallets, setWallets] = useState<Wallet[]>([])
  const [name, setName] = useState('')
  const [walletId, setWalletId] = useState('')
  const [recipientAddress, setRecipientAddress] = useState('')
  const [chain, setChain] = useState('ethereum')
  const [token, setToken] = useState('')
  const [amount, setAmount] = useState('')
  const [interval, setInterval] = useState('monthly')
  const [requireBalance, setRequireBalance] = useState(true)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    api.listVaults().then(async (vaults: Vault[]) => {
      const all: Wallet[] = []
      for (const v of vaults) {
        const ws = await api.listWallets(v.id)
        all.push(...ws)
      }
      setWallets(all)
      if (all.length > 0) setWalletId(all[0].id)
    }).catch(() => {})
  }, [])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      const sub = await api.createSubscription({
        wallet_id: walletId,
        name,
        recipient_address: recipientAddress,
        chain,
        token: token || undefined,
        amount,
        interval,
        require_balance: requireBalance,
      })
      router.push(`/subscriptions/${sub.id}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create subscription')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/subscriptions" className="hover:text-foreground">Subscriptions</Link>
          <span>/</span>
          <span>New</span>
        </div>

        <h1 className="mb-8 text-2xl font-semibold tracking-tight">Create Subscription</h1>

        <div className="mx-auto max-w-lg">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Cloud Hosting"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Wallet</label>
              <select
                required
                value={walletId}
                onChange={(e) => setWalletId(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Select wallet...</option>
                {wallets.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name || w.wallet_id} ({w.key_type})
                  </option>
                ))}
              </select>
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
                <label className="text-sm font-medium text-muted-foreground">Token (optional)</label>
                <input
                  type="text"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="USDC"
                />
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
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

              <div className="space-y-1.5">
                <label className="text-sm font-medium text-muted-foreground">Interval</label>
                <select
                  value={interval}
                  onChange={(e) => setInterval(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  {intervals.map((i) => (
                    <option key={i} value={i}>{i}</option>
                  ))}
                </select>
              </div>
            </div>

            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={requireBalance}
                onChange={(e) => setRequireBalance(e.target.checked)}
                className="rounded border-input"
              />
              <span className="text-sm text-muted-foreground">Require sufficient balance before payment</span>
            </label>

            {error && <p className="text-sm text-destructive">{error}</p>}

            <button
              type="submit"
              disabled={submitting || !name || !walletId || !recipientAddress || !amount}
              className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {submitting ? 'Creating...' : 'Create Subscription'}
            </button>
          </form>
        </div>
      </main>
    </>
  )
}
