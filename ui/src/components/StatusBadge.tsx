const colors: Record<string, { bg: string; fg: string }> = {
  running:    { bg: '#22c55e20', fg: '#22c55e' },
  active:     { bg: '#22c55e20', fg: '#22c55e' },
  enabled:    { bg: '#22c55e20', fg: '#22c55e' },
  finalized:  { bg: '#22c55e20', fg: '#22c55e' },
  verified:   { bg: '#22c55e20', fg: '#22c55e' },
  signed:     { bg: '#22c55e20', fg: '#22c55e' },
  paid:       { bg: '#22c55e20', fg: '#22c55e' },
  pending:    { bg: '#f59e0b20', fg: '#f59e0b' },
  pending_approval: { bg: '#f59e0b20', fg: '#f59e0b' },
  pending_sign:     { bg: '#f59e0b20', fg: '#f59e0b' },
  hsm_signing:      { bg: '#f59e0b20', fg: '#f59e0b' },
  confirming: { bg: '#f59e0b20', fg: '#f59e0b' },
  broadcast:  { bg: '#3b82f620', fg: '#3b82f6' },
  settling:   { bg: '#3b82f620', fg: '#3b82f6' },
  signing:    { bg: '#3b82f620', fg: '#3b82f6' },
  degraded:   { bg: '#f9731620', fg: '#f97316' },
  resharing:  { bg: '#f9731620', fg: '#f97316' },
  failed:     { bg: '#ef444420', fg: '#ef4444' },
  rejected:   { bg: '#ef444420', fg: '#ef4444' },
  disabled:   { bg: '#52525220', fg: '#737373' },
  archived:   { bg: '#52525220', fg: '#737373' },
  expired:    { bg: '#52525220', fg: '#737373' },
  cancelled:  { bg: '#52525220', fg: '#737373' },
}

const fallback = { bg: '#26262620', fg: '#a3a3a3' }

export function StatusBadge({ status }: { status: string }) {
  const c = colors[status] ?? fallback
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: 12,
        background: c.bg,
        color: c.fg,
      }}
    >
      {status.replace(/_/g, ' ')}
    </span>
  )
}
