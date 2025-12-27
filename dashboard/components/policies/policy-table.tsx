import Link from 'next/link'

export interface Policy {
  id: string
  name: string
  type: 'spend_limit' | 'whitelist' | 'time_lock' | 'quorum' | 'custom'
  status: 'active' | 'disabled'
  conditions: string
  appliedTo: string
  createdAt: string
}

export interface PolicyTableProps {
  policies: Policy[]
}

const typeLabels: Record<string, string> = {
  spend_limit: 'Spend Limit',
  whitelist: 'Whitelist',
  time_lock: 'Time Lock',
  quorum: 'Quorum',
  custom: 'Custom',
}

export function PolicyTable({ policies }: PolicyTableProps) {
  if (policies.length === 0) {
    return (
      <div className="rounded-lg border border-border p-8 text-center text-sm text-muted-foreground">
        No policies configured.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Name</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Conditions</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Applied To</th>
            <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
            <th className="px-4 py-3 text-right font-medium text-muted-foreground">Created</th>
          </tr>
        </thead>
        <tbody>
          {policies.map((policy) => (
            <tr key={policy.id} className="border-b border-border last:border-0 hover:bg-muted/20">
              <td className="px-4 py-3">
                <Link href={`/policies/${policy.id}`} className="font-medium hover:underline">
                  {policy.name}
                </Link>
              </td>
              <td className="px-4 py-3">
                <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
                  {typeLabels[policy.type] ?? policy.type}
                </span>
              </td>
              <td className="px-4 py-3 text-muted-foreground max-w-[200px] truncate">
                {policy.conditions}
              </td>
              <td className="px-4 py-3 font-mono text-xs">{policy.appliedTo}</td>
              <td className="px-4 py-3">
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                    policy.status === 'active'
                      ? 'bg-green-600/20 text-green-500'
                      : 'bg-zinc-600/20 text-zinc-400'
                  }`}
                >
                  {policy.status}
                </span>
              </td>
              <td className="px-4 py-3 text-right text-muted-foreground">
                {new Date(policy.createdAt).toLocaleDateString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
