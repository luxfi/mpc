const statusColors: Record<string, string> = {
  active: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  running: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  signed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  approved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  enabled: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  pending: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  pending_approval: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  signing: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  processing: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  failed: 'bg-red-500/10 text-red-400 border-red-500/20',
  rejected: 'bg-red-500/10 text-red-400 border-red-500/20',
  cancelled: 'bg-red-500/10 text-red-400 border-red-500/20',
  disabled: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
  paused: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
  inactive: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
}

interface StatusBadgeProps {
  status: string
  className?: string
}

export function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const colorClasses = statusColors[status.toLowerCase()] ?? 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize ${colorClasses} ${className}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  )
}
