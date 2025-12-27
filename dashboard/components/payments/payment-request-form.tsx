'use client'

import { useState } from 'react'

const chains = [
  { name: 'Ethereum', chainId: 1 },
  { name: 'Lux C-Chain', chainId: 96369 },
  { name: 'Lux Testnet', chainId: 96368 },
  { name: 'Zoo', chainId: 200200 },
  { name: 'Hanzo', chainId: 36963 },
]

export interface PaymentRequestFormData {
  walletId: string
  merchantName: string
  recipientAddress: string
  chain: string
  chainId: number
  amount: string
  memo: string
  expiryHours: number
}

export interface PaymentRequestFormProps {
  walletId?: string
  onSubmit: (data: PaymentRequestFormData) => void
  onCancel: () => void
  submitting?: boolean
}

export function PaymentRequestForm({
  walletId = '',
  onSubmit,
  onCancel,
  submitting = false,
}: PaymentRequestFormProps) {
  const [form, setForm] = useState<PaymentRequestFormData>({
    walletId,
    merchantName: '',
    recipientAddress: '',
    chain: chains[0].name,
    chainId: chains[0].chainId,
    amount: '',
    memo: '',
    expiryHours: 24,
  })

  function update<K extends keyof PaymentRequestFormData>(
    field: K,
    value: PaymentRequestFormData[K]
  ) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSubmit(form)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {!walletId && (
        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="pr-wallet">
            Wallet ID (optional)
          </label>
          <input
            id="pr-wallet"
            type="text"
            value={form.walletId}
            onChange={(e) => update('walletId', e.target.value)}
            placeholder="Leave empty for any wallet"
            className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
      )}

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="pr-merchant">
          Merchant Name
        </label>
        <input
          id="pr-merchant"
          type="text"
          value={form.merchantName}
          onChange={(e) => update('merchantName', e.target.value)}
          placeholder="Your business name"
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="pr-recipient">
          Recipient Address
        </label>
        <input
          id="pr-recipient"
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
          <label className="text-sm font-medium" htmlFor="pr-chain">
            Chain
          </label>
          <select
            id="pr-chain"
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
          <label className="text-sm font-medium" htmlFor="pr-amount">
            Amount
          </label>
          <input
            id="pr-amount"
            type="text"
            required
            value={form.amount}
            onChange={(e) => update('amount', e.target.value)}
            placeholder="e.g. 100 USDC"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="pr-memo">
          Memo
        </label>
        <input
          id="pr-memo"
          type="text"
          value={form.memo}
          onChange={(e) => update('memo', e.target.value)}
          placeholder="Optional note"
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="pr-expiry">
          Expiry (hours)
        </label>
        <input
          id="pr-expiry"
          type="number"
          min={1}
          max={720}
          value={form.expiryHours}
          onChange={(e) => update('expiryHours', Number(e.target.value))}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
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
          disabled={submitting || !form.recipientAddress || !form.amount}
          className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {submitting ? 'Creating...' : 'Create Request'}
        </button>
      </div>
    </form>
  )
}
