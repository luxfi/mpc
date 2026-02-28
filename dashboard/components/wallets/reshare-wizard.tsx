'use client'

export interface ReshareWizardProps {
  step: 'configuring' | 'confirming' | 'resharing' | 'complete' | 'error'
  threshold: number
  participants: string[]
  error?: string
}

export function ReshareWizard({ step, threshold, participants, error }: ReshareWizardProps) {
  const steps = ['Configure', 'Confirm', 'Reshare', 'Complete']
  const stepIndex = { configuring: 0, confirming: 1, resharing: 2, complete: 3, error: 2 }

  const current = stepIndex[step]

  return (
    <div className="space-y-6">
      {/* Step indicators */}
      <div className="flex items-center justify-between">
        {steps.map((label, i) => (
          <div key={label} className="flex items-center gap-2">
            <div
              className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-medium ${
                i < current
                  ? 'bg-primary text-primary-foreground'
                  : i === current
                    ? 'border-2 border-primary text-primary'
                    : 'border border-border text-muted-foreground'
              }`}
            >
              {i < current ? '\u2713' : i + 1}
            </div>
            <span
              className={`hidden text-xs sm:inline ${
                i <= current ? 'text-foreground' : 'text-muted-foreground'
              }`}
            >
              {label}
            </span>
            {i < steps.length - 1 && (
              <div
                className={`mx-2 hidden h-px w-8 sm:block ${
                  i < current ? 'bg-primary' : 'bg-border'
                }`}
              />
            )}
          </div>
        ))}
      </div>

      {/* Reshare progress */}
      {step === 'resharing' && (
        <div className="rounded-lg border border-border bg-card p-6 text-center space-y-4">
          <div className="mx-auto h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="text-sm font-medium">Resharing Key Shares</p>
          <p className="text-xs text-muted-foreground">
            Rotating to {threshold}-of-{participants.length} configuration.
            All participants must remain online.
          </p>
          <div className="space-y-1 text-xs text-muted-foreground">
            {participants.map((p) => (
              <p key={p} className="font-mono">{p}</p>
            ))}
          </div>
        </div>
      )}

      {step === 'error' && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-6 text-center">
          <p className="text-sm font-medium text-destructive">Reshare Failed</p>
          {error && <p className="mt-1 text-xs text-destructive/80">{error}</p>}
        </div>
      )}
    </div>
  )
}
