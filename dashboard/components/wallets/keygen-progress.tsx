'use client'

export interface KeygenProgressProps {
  status: 'waiting' | 'round1' | 'round2' | 'round3' | 'round4' | 'finalizing' | 'complete' | 'error'
  protocol: 'cggmp21' | 'frost' | 'lss'
  participants: number
  readyCount?: number
  error?: string
}

const roundLabels: Record<string, string[]> = {
  cggmp21: ['Waiting for peers', 'Round 1: Commitments', 'Round 2: Shares', 'Round 3: Proofs', 'Round 4: Verification', 'Finalizing', 'Complete'],
  frost: ['Waiting for peers', 'Round 1: Commitments', 'Round 2: Shares', 'Verification', '', 'Finalizing', 'Complete'],
  lss: ['Waiting for peers', 'Round 1: Commitments', 'Round 2: Share Distribution', 'Round 3: Verification', '', 'Finalizing', 'Complete'],
}

const statusToIndex: Record<string, number> = {
  waiting: 0,
  round1: 1,
  round2: 2,
  round3: 3,
  round4: 4,
  finalizing: 5,
  complete: 6,
  error: -1,
}

export function KeygenProgress({
  status,
  protocol,
  participants,
  readyCount = 0,
  error,
}: KeygenProgressProps) {
  const labels = roundLabels[protocol] ?? roundLabels.cggmp21
  const currentIndex = statusToIndex[status] ?? 0
  const totalSteps = labels.filter(Boolean).length

  if (status === 'error') {
    return (
      <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-6 text-center">
        <div className="mx-auto mb-3 h-8 w-8 rounded-full border-2 border-destructive flex items-center justify-center text-destructive text-sm font-bold">
          !
        </div>
        <p className="text-sm font-medium text-destructive">Key Generation Failed</p>
        {error && <p className="mt-1 text-xs text-destructive/80">{error}</p>}
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-border bg-card p-6 space-y-4">
      <div className="flex items-center justify-center gap-3">
        {status !== 'complete' && (
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        )}
        <span className="text-sm font-medium">
          {status === 'complete'
            ? 'Key Generation Complete'
            : labels[currentIndex] || 'Processing...'}
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-2 w-full rounded-full bg-muted">
        <div
          className="h-2 rounded-full bg-primary transition-all duration-500"
          style={{ width: `${Math.max(5, (currentIndex / (totalSteps - 1)) * 100)}%` }}
        />
      </div>

      {/* Step indicators */}
      <div className="flex justify-between text-xs text-muted-foreground">
        {labels.filter(Boolean).map((label, i) => (
          <span
            key={label}
            className={i <= currentIndex ? 'text-foreground' : ''}
          >
            {i + 1}
          </span>
        ))}
      </div>

      {status === 'waiting' && (
        <p className="text-center text-xs text-muted-foreground">
          {readyCount} of {participants} participants ready
        </p>
      )}
    </div>
  )
}
