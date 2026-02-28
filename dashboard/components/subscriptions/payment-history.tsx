export interface PaymentRecord {
  id: string
  txHash: string
  amount: string
  token: string
  status: 'confirmed' | 'pending' | 'failed'
  paidAt: string
}

export interface PaymentHistoryProps {
  payments: PaymentRecord[]
}

const statusColors: Record<string, string> = {
  confirmed: 'bg-green-600/20 text-green-500',
  pending: 'bg-yellow-600/20 text-yellow-500',
  failed: 'bg-red-600/20 text-red-400',
}

export function PaymentHistory({ payments }: PaymentHistoryProps) {
  if (payments.length === 0) {
    return (
      <div className="rounded-lg border border-border p-8 text-center text-sm text-muted-foreground">
        No payments recorded yet.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Date</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Amount</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Tx Hash</th>
          </tr>
        </thead>
        <tbody>
          {payments.map((p) => (
            <tr key={p.id} className="border-b border-border last:border-0 hover:bg-muted/20">
              <td className="px-4 py-3 text-muted-foreground">
                {new Date(p.paidAt).toLocaleDateString()}
              </td>
              <td className="px-4 py-3 text-right font-mono">{p.amount}</td>
              <td className="px-4 py-3">
                <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusColors[p.status] ?? ''}`}>
                  {p.status}
                </span>
              </td>
              <td className="px-4 py-3 font-mono text-xs">
                <span className="truncate block max-w-[200px]">{p.txHash}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
