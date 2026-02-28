'use client'

import { useState } from 'react'

const chains = [
  { name: 'Ethereum', chainId: 1 },
  { name: 'Lux C-Chain', chainId: 96369 },
  { name: 'Lux Testnet', chainId: 96368 },
  { name: 'Zoo', chainId: 200200 },
  { name: 'Hanzo', chainId: 36963 },
]

const intervals = ['daily', 'weekly', 'monthly', 'quarterly', 'yearly']

export interface SubscriptionFormData {
  name: string
  provider: string
  walletId: string
  recipientAddress: string
  chain: string
  chainId: number
  amount: string
  token: string
  interval: string
}

export interface SubscriptionFormProps {
  walletId?: string
  onSubmit: (data: SubscriptionFormData) => void
  onCancel: () => void
  submitting?: boolean
}

export function SubscriptionForm({
  walletId = '',
  onSubmit,
  onCancel,
  submitting = false,
}: SubscriptionFormProps) {
  const [form, setForm] = useState<SubscriptionFormData>({
    name: '',
    provider: '',
    walletId,
    recipientAddress: '',
    chain: chains[0].name,
    chainId: chains[0].chainId,
    amount: '',
    token: 'USDC',
    interval: 'monthly',
  })

  function update<K extends keyof SubscriptionFormData>(
    field: K,
    value: SubscriptionFormData[K]
  ) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSubmit(form)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="sub-name">
            Subscription Name
          </label>
          <input
            id="sub-name"
            type="text"
            required
            value={form.name}
            onChange={(e) => update('name', e.target.value)}
            placeholder="e.g. Cloud Hosting"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="sub-provider">
            Provider
          </label>
          <input
            id="sub-provider"
            type="text"
            required
            value={form.provider}
            onChange={(e) => update('provider', e.target.value)}
            placeholder="Provider name"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
      </div>

      {!walletId && (
        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="sub-wallet">
            Wallet ID
          </label>
          <input
            id="sub-wallet"
            type="text"
            required
            value={form.walletId}
            onChange={(e) => update('walletId', e.target.value)}
            placeholder="wallet-..."
            className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
      )}

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="sub-recipient">
          Recipient Address
        </label>
        <input
          id="sub-recipient"
          type="text"
          required
          value={form.recipientAddress}
          onChange={(e) => update('recipientAddress', e.target.value)}
          placeholder="0x..."
          className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="sub-chain">
            Chain
          </label>
          <select
            id="sub-chain"
            value={form.chainId}
            onChange={(e) => {
              const chain = chains.find((c) => c.chainId === Number(e.target.value))
              if (chain) {
                setForm((f) => ({ ...f, chain: chain.name, chainId: chain.chainId }))
              }
            }}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            {chains.map((c) => (
              <option key={c.chainId} value={c.chainId}>
                {c.name}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="sub-interval">
            Interval
          </label>
          <select
            id="sub-interval"
            value={form.interval}
            onChange={(e) => update('interval', e.target.value)}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            {intervals.map((i) => (
              <option key={i} value={i}>
                {i.charAt(0).toUpperCase() + i.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="sub-amount">
            Amount
          </label>
          <input
            id="sub-amount"
            type="text"
            required
            value={form.amount}
            onChange={(e) => update('amount', e.target.value)}
            placeholder="e.g. 100"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="sub-token">
            Token
          </label>
          <input
            id="sub-token"
            type="text"
            required
            value={form.token}
            onChange={(e) => update('token', e.target.value)}
            placeholder="e.g. USDC, ETH"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
      </div>

      <div className="flex gap-3 pt-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={submitting}
          className="flex-1 rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting || !form.name || !form.recipientAddress || !form.amount}
          className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {submitting ? 'Creating...' : 'Create Subscription'}
        </button>
      </div>
    </form>
  )
}
