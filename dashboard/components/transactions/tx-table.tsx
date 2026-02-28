import Link from 'next/link'

export interface Transaction {
  id: string
  type: string
  status: 'pending' | 'confirmed' | 'failed' | 'awaiting_approval'
  chain: string
  from: string
  to: string
  value: string
  hash?: string
  timestamp: string
}

export interface TxTableProps {
  transactions: Transaction[]
}

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-600/20 text-yellow-500',
  confirmed: 'bg-green-600/20 text-green-500',
  failed: 'bg-red-600/20 text-red-400',
  awaiting_approval: 'bg-blue-600/20 text-blue-400',
}

export function TxTable({ transactions }: TxTableProps) {
  if (transactions.length === 0) {
    return (
      <div className="rounded-lg border border-border p-8 text-center text-sm text-muted-foreground">
        No transactions found.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">From</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">To</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Value</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Time</th>
          </tr>
        </thead>
        <tbody>
          {transactions.map((tx) => (
            <tr key={tx.id} className="border-b border-border last:border-0 hover:bg-muted/20">
              <td className="px-4 py-3">
                <Link href={`/transactions/${tx.id}`} className="font-medium hover:underline">
                  {tx.type}
                </Link>
              </td>
              <td className="px-4 py-3">
                <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusColors[tx.status] ?? ''}`}>
                  {tx.status.replace('_', ' ')}
                </span>
              </td>
              <td className="px-4 py-3">{tx.chain}</td>
              <td className="px-4 py-3 font-mono text-xs">
                <span className="truncate block max-w-[120px]">{tx.from}</span>
              </td>
              <td className="px-4 py-3 font-mono text-xs">
                <span className="truncate block max-w-[120px]">{tx.to}</span>
              </td>
              <td className="px-4 py-3 text-right font-mono">{tx.value}</td>
              <td className="px-4 py-3 text-right text-muted-foreground">
                {new Date(tx.timestamp).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
