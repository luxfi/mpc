'use client'

import { useState } from 'react'

const chains = [
  { name: 'Ethereum', chainId: 1 },
  { name: 'Lux C-Chain', chainId: 96369 },
  { name: 'Lux Testnet', chainId: 96368 },
  { name: 'Zoo', chainId: 200200 },
  { name: 'Hanzo', chainId: 36963 },
  { name: 'Bitcoin', chainId: 0 },
]

export interface TxFormData {
  walletId: string
  chain: string
  chainId: number
  to: string
  value: string
  data: string
  memo: string
}

export interface TxFormProps {
  walletId?: string
  onSubmit: (data: TxFormData) => void
  onCancel: () => void
  submitting?: boolean
}

export function TxForm({ walletId = '', onSubmit, onCancel, submitting = false }: TxFormProps) {
  const [form, setForm] = useState<TxFormData>({
    walletId,
    chain: chains[0].name,
    chainId: chains[0].chainId,
    to: '',
    value: '',
    data: '',
    memo: '',
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSubmit(form)
  }

  function update(field: keyof TxFormData, value: string | number) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {!walletId && (
        <div className="space-y-2">
          <label className="text-sm font-medium" htmlFor="tx-wallet">
            Wallet ID
          </label>
          <input
            id="tx-wallet"
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
        <label className="text-sm font-medium" htmlFor="tx-chain">
          Chain
        </label>
        <select
          id="tx-chain"
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
        <label className="text-sm font-medium" htmlFor="tx-to">
          Recipient Address
        </label>
        <input
          id="tx-to"
          type="text"
          required
          value={form.to}
          onChange={(e) => update('to', e.target.value)}
          placeholder="0x..."
          className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="tx-value">
          Value
        </label>
        <input
          id="tx-value"
          type="text"
          required
          value={form.value}
          onChange={(e) => update('value', e.target.value)}
          placeholder="e.g. 1.5"
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="tx-data">
          Calldata (optional)
        </label>
        <textarea
          id="tx-data"
          value={form.data}
          onChange={(e) => update('data', e.target.value)}
          placeholder="0x..."
          rows={3}
          className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="tx-memo">
          Memo
        </label>
        <input
          id="tx-memo"
          type="text"
          value={form.memo}
          onChange={(e) => update('memo', e.target.value)}
          placeholder="Optional note"
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
          disabled={submitting || !form.to || !form.value}
          className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {submitting ? 'Submitting...' : 'Create Transaction'}
        </button>
      </div>
    </form>
  )
}
