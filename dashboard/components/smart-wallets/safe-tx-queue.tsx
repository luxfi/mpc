'use client'

interface PendingSafeTx {
  id: string
  to: string
  value: string
  data: string
  nonce: number
  confirmations: number
  required: number
  submittedBy: string
  createdAt: string
}

interface SafeTxQueueProps {
  transactions: PendingSafeTx[]
  walletId: string
}

export function SafeTxQueue({ transactions, walletId }: SafeTxQueueProps) {
  if (transactions.length === 0) {
    return (
      <div className="rounded-lg border border-border p-8 text-center text-sm text-muted-foreground">
        No pending transactions.
      </div>
    )
  }

  async function handleConfirm(txId: string) {
    // TODO: call API to confirm Safe transaction
    console.log('Confirm tx', txId, 'on wallet', walletId)
  }

  async function handleExecute(txId: string) {
    // TODO: call API to execute Safe transaction
    console.log('Execute tx', txId, 'on wallet', walletId)
  }

  return (
    <div className="space-y-3">
      {transactions.map((tx) => (
        <div
          key={tx.id}
          className="rounded-lg border border-border bg-card p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-muted-foreground">
              Nonce #{tx.nonce}
            </span>
            <span className="text-xs text-muted-foreground">
              {tx.confirmations}/{tx.required} confirmations
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">To</p>
              <p className="truncate font-mono text-xs">{tx.to}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Value</p>
              <p className="font-mono text-xs">{tx.value}</p>
            </div>
          </div>
          {tx.data !== '0x' && (
            <div>
              <p className="text-xs text-muted-foreground">Data</p>
              <p className="truncate font-mono text-xs">{tx.data}</p>
            </div>
          )}
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              By: {tx.submittedBy} at {new Date(tx.createdAt).toLocaleString()}
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => handleConfirm(tx.id)}
                className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground hover:bg-accent"
              >
                Confirm
              </button>
              {tx.confirmations >= tx.required && (
                <button
                  onClick={() => handleExecute(tx.id)}
                  className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
                >
                  Execute
                </button>
              )}
            </div>
          </div>
          {/* Progress bar */}
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all"
              style={{ width: `${(tx.confirmations / tx.required) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}
