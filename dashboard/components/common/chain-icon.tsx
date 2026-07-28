// Chain badges are third-party identity, and lux/brand DESIGN.md §1.2 reserves
// hue for exactly that ("state, market direction, and chain badges"). Bitcoin is
// orange because Bitcoin is orange — this is not Lux chrome and stays as-is.
const chainMeta: Record<string, { label: string; color: string }> = {
  ethereum: { label: 'Ethereum', color: 'text-foreground' },
  bitcoin: { label: 'Bitcoin', color: 'text-[var(--color-status-warn)]' },
  solana: { label: 'Solana', color: 'text-foreground' },
  lux: { label: 'Lux', color: 'text-zinc-300' },
  xrpl: { label: 'XRPL', color: 'text-zinc-400' },
  ton: { label: 'TON', color: 'text-foreground' },
}

interface ChainIconProps {
  chain: string
  className?: string
}

export function ChainIcon({ chain, className = '' }: ChainIconProps) {
  const meta = chainMeta[chain.toLowerCase()] ?? { label: chain, color: 'text-muted-foreground' }
  return (
    <span className={`inline-flex items-center gap-1.5 text-sm font-medium ${meta.color} ${className}`}>
      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-muted text-[10px] font-bold uppercase">
        {meta.label.charAt(0)}
      </span>
      {meta.label}
    </span>
  )
}
