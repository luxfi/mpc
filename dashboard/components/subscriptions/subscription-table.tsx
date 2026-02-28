import Link from 'next/link'

export interface SubscriptionRow {
  id: string
  name: string
  provider: string
  chain: string
  amount: string
  token: string
  interval: string
  status: 'active' | 'paused' | 'cancelled'
  nextPaymentAt: string
}

export interface SubscriptionTableProps {
  subscriptions: SubscriptionRow[]
}

const statusColors: Record<string, string> = {
  active: 'bg-green-600/20 text-green-500',
  paused: 'bg-yellow-600/20 text-yellow-500',
  cancelled: 'bg-zinc-600/20 text-zinc-400',
}

export function SubscriptionTable({ subscriptions }: SubscriptionTableProps) {
  if (subscriptions.length === 0) {
    return (
      <div className="rounded-lg border border-border p-8 text-center text-sm text-muted-foreground">
        No subscriptions found.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Name</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Provider</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Amount</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Interval</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Next Payment</th>
          </tr>
        </thead>
        <tbody>
          {subscriptions.map((sub) => (
            <tr key={sub.id} className="border-b border-border last:border-0 hover:bg-muted/20">
              <td className="px-4 py-3">
                <Link href={`/subscriptions/${sub.id}`} className="font-medium hover:underline">
                  {sub.name}
                </Link>
              </td>
              <td className="px-4 py-3 text-muted-foreground">{sub.provider}</td>
              <td className="px-4 py-3">{sub.chain}</td>
              <td className="px-4 py-3 text-right font-mono">
                {sub.amount} {sub.token}
              </td>
              <td className="px-4 py-3 capitalize">{sub.interval}</td>
              <td className="px-4 py-3">
                <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusColors[sub.status] ?? ''}`}>
                  {sub.status}
                </span>
              </td>
              <td className="px-4 py-3 text-right text-muted-foreground">
                {sub.status !== 'cancelled'
                  ? new Date(sub.nextPaymentAt).toLocaleDateString()
                  : '-'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
