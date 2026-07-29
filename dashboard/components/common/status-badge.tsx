// Status is a TONE, not a hue. Lux permits exactly two hues — success and error
// — and carries everything else on the achromatic ladder, so `pending` no longer
// paints itself amber. Tones resolve through @luxfi/ui/tokens.css, which means a
// white-label host retints them without a rebuild.
const TONE_CLASS = {
  good: 'bg-[var(--muted)] text-good border-[var(--border)]',
  bad: 'bg-[var(--muted)] text-bad border-[var(--border)]',
  // Waiting on someone. The loudest neutral — was amber-400 on amber-500/10.
  pending: 'bg-[var(--muted)] text-warn border-[var(--border)]',
  // Work in flight. Full-contrast neutral — was blue-400 on blue-500/10.
  active: 'bg-[var(--secondary)] text-[var(--foreground)] border-[var(--border)]',
  // Nothing is happening.
  inert: 'bg-[var(--muted)] text-[var(--muted-foreground)] border-[var(--border)]',
} as const

type Tone = keyof typeof TONE_CLASS

const STATUS_TONE: Record<string, Tone> = {
  active: 'good', running: 'good', signed: 'good', approved: 'good',
  enabled: 'good', settled: 'good', verified: 'good', finalized: 'good',
  co_signed: 'good',
  pending: 'pending', pending_approval: 'pending', pending_sign: 'pending',
  matched: 'pending',
  signing: 'active', processing: 'active', settling: 'active',
  hsm_signing: 'active', confirming: 'active', broadcast: 'active',
  recorded: 'active',
  failed: 'bad', rejected: 'bad', cancelled: 'bad',
  expired: 'inert', disabled: 'inert', paused: 'inert', inactive: 'inert',
}

interface StatusBadgeProps {
  status: string
  className?: string
}

export function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const tone = STATUS_TONE[status.toLowerCase()] ?? 'inert'
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize ${TONE_CLASS[tone]} ${className}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  )
}
