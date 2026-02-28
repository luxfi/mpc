export interface TxDetailData {
  id: string
  type: string
  status: string
  chain: string
  chainId: number
  from: string
  to: string
  value: string
  hash?: string
  data?: string
  nonce?: number
  gasUsed?: string
  gasPrice?: string
  blockNumber?: number
  memo?: string
  createdAt: string
  confirmedAt?: string
  approvals?: { address: string; approved: boolean; timestamp: string }[]
}

export interface TxDetailProps {
  transaction: TxDetailData
}

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-600/20 text-yellow-500',
  confirmed: 'bg-green-600/20 text-green-500',
  failed: 'bg-red-600/20 text-red-400',
  awaiting_approval: 'bg-blue-600/20 text-blue-400',
}

export function TxDetail({ transaction: tx }: TxDetailProps) {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <span
          className={`rounded-full px-3 py-1 text-xs font-medium ${statusColors[tx.status] ?? 'bg-muted text-muted-foreground'}`}
        >
          {tx.status.replace('_', ' ')}
        </span>
        <span className="text-sm text-muted-foreground">{tx.type}</span>
      </div>

      <dl className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-muted-foreground">Chain</dt>
          <dd className="mt-1">
            {tx.chain} ({tx.chainId})
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Transaction ID</dt>
          <dd className="mt-1 font-mono text-xs">{tx.id}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-muted-foreground">From</dt>
          <dd className="mt-1 truncate font-mono text-xs">{tx.from}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-muted-foreground">To</dt>
          <dd className="mt-1 truncate font-mono text-xs">{tx.to}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Value</dt>
          <dd className="mt-1 font-mono">{tx.value}</dd>
        </div>
        {tx.hash && (
          <div>
            <dt className="text-muted-foreground">Tx Hash</dt>
            <dd className="mt-1 truncate font-mono text-xs">{tx.hash}</dd>
          </div>
        )}
        {tx.nonce != null && (
          <div>
            <dt className="text-muted-foreground">Nonce</dt>
            <dd className="mt-1 font-mono">{tx.nonce}</dd>
          </div>
        )}
        {tx.blockNumber != null && (
          <div>
            <dt className="text-muted-foreground">Block</dt>
            <dd className="mt-1 font-mono">{tx.blockNumber}</dd>
          </div>
        )}
        {tx.gasUsed && (
          <div>
            <dt className="text-muted-foreground">Gas Used</dt>
            <dd className="mt-1 font-mono">{tx.gasUsed}</dd>
          </div>
        )}
        {tx.gasPrice && (
          <div>
            <dt className="text-muted-foreground">Gas Price</dt>
            <dd className="mt-1 font-mono">{tx.gasPrice}</dd>
          </div>
        )}
        {tx.data && (
          <div className="sm:col-span-2">
            <dt className="text-muted-foreground">Calldata</dt>
            <dd className="mt-1 break-all font-mono text-xs">{tx.data}</dd>
          </div>
        )}
        {tx.memo && (
          <div className="sm:col-span-2">
            <dt className="text-muted-foreground">Memo</dt>
            <dd className="mt-1">{tx.memo}</dd>
          </div>
        )}
        <div>
          <dt className="text-muted-foreground">Created</dt>
          <dd className="mt-1">{new Date(tx.createdAt).toLocaleString()}</dd>
        </div>
        {tx.confirmedAt && (
          <div>
            <dt className="text-muted-foreground">Confirmed</dt>
            <dd className="mt-1">{new Date(tx.confirmedAt).toLocaleString()}</dd>
          </div>
        )}
      </dl>

      {tx.approvals && tx.approvals.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground">Approvals</h3>
          <div className="space-y-1">
            {tx.approvals.map((a) => (
              <div
                key={a.address}
                className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-xs"
              >
                <span className="truncate font-mono">{a.address}</span>
                <span className={a.approved ? 'text-green-500' : 'text-yellow-500'}>
                  {a.approved ? 'Approved' : 'Pending'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
