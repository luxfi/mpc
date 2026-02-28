export interface ChainAddress {
  chain: string
  chainId?: number
  address: string
  format?: string
}

export interface AddressListProps {
  addresses: ChainAddress[]
}

export function AddressList({ addresses }: AddressListProps) {
  if (addresses.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No derived addresses.</p>
    )
  }

  return (
    <div className="space-y-2">
      {addresses.map((a) => (
        <div
          key={`${a.chain}-${a.address}`}
          className="flex items-center justify-between rounded-md border border-border bg-muted/30 px-3 py-2"
        >
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium">
              {a.chain}
              {a.chainId != null && (
                <span className="ml-1 text-muted-foreground">({a.chainId})</span>
              )}
              {a.format && (
                <span className="ml-2 text-muted-foreground">[{a.format}]</span>
              )}
            </p>
            <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
              {a.address}
            </p>
          </div>
          <button
            onClick={() => navigator.clipboard.writeText(a.address)}
            className="ml-2 shrink-0 rounded px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          >
            Copy
          </button>
        </div>
      ))}
    </div>
  )
}
