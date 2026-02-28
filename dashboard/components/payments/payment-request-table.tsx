import Link from 'next/link'

export interface PaymentRequest {
  id: string
  merchantName: string
  recipientAddress: string
  chain: string
  amount: string
  status: 'open' | 'paid' | 'expired' | 'cancelled'
  expiresAt: string
  createdAt: string
}

export interface PaymentRequestTableProps {
  requests: PaymentRequest[]
}

const statusColors: Record<string, string> = {
  open: 'bg-blue-600/20 text-blue-400',
  paid: 'bg-green-600/20 text-green-500',
  expired: 'bg-zinc-600/20 text-zinc-400',
  cancelled: 'bg-red-600/20 text-red-400',
}

export function PaymentRequestTable({ requests }: PaymentRequestTableProps) {
  if (requests.length === 0) {
    return (
      <div className="rounded-lg border border-border p-8 text-center text-sm text-muted-foreground">
        No payment requests found.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Merchant</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Recipient</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Amount</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Expires</th>
          </tr>
        </thead>
        <tbody>
          {requests.map((req) => (
            <tr key={req.id} className="border-b border-border last:border-0 hover:bg-muted/20">
              <td className="px-4 py-3">
                <Link href={`/payments/${req.id}`} className="font-medium hover:underline">
                  {req.merchantName || 'Unnamed'}
                </Link>
              </td>
              <td className="px-4 py-3 font-mono text-xs">
                <span className="truncate block max-w-[140px]">{req.recipientAddress}</span>
              </td>
              <td className="px-4 py-3">{req.chain}</td>
              <td className="px-4 py-3 text-right font-mono">{req.amount}</td>
              <td className="px-4 py-3">
                <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusColors[req.status] ?? ''}`}>
                  {req.status}
                </span>
              </td>
              <td className="px-4 py-3 text-right text-muted-foreground">
                {new Date(req.expiresAt).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
