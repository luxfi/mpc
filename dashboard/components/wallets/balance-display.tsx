export interface Balance {
  chain: string
  token: string
  amount: string
  usdValue?: string
}

export interface BalanceDisplayProps {
  balances: Balance[]
  loading?: boolean
}

export function BalanceDisplay({ balances, loading = false }: BalanceDisplayProps) {
  if (loading) {
    return (
      <div className="space-y-2">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="h-10 animate-pulse rounded-md bg-muted"
          />
        ))}
      </div>
    )
  }

  if (balances.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No balances found.</p>
    )
  }

  return (
    <div className="space-y-1">
      {balances.map((b) => (
        <div
          key={`${b.chain}-${b.token}`}
          className="flex items-center justify-between rounded-md px-3 py-2 text-sm hover:bg-muted/30"
        >
          <div>
            <span className="font-medium">{b.token}</span>
            <span className="ml-2 text-xs text-muted-foreground">{b.chain}</span>
          </div>
          <div className="text-right">
            <span className="font-mono">{b.amount}</span>
            {b.usdValue && (
              <span className="ml-2 text-xs text-muted-foreground">
                ${b.usdValue}
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
