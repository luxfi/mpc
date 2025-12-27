interface DeployWizardProps {
  currentStep: 'type' | 'config' | 'advanced' | 'deploy'
}

const steps = [
  { key: 'type', label: 'Type' },
  { key: 'config', label: 'Config' },
  { key: 'advanced', label: 'Advanced' },
  { key: 'deploy', label: 'Deploy' },
] as const

export function DeployWizard({ currentStep }: DeployWizardProps) {
  const currentIndex = steps.findIndex((s) => s.key === currentStep)

  return (
    <div className="flex items-center justify-between">
      {steps.map((step, i) => (
        <div key={step.key} className="flex items-center gap-2">
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold ${
              step.key === currentStep
                ? 'bg-primary text-primary-foreground'
                : i < currentIndex
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : 'bg-muted text-muted-foreground'
            }`}
          >
            {i < currentIndex ? (
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            ) : (
              i + 1
            )}
          </div>
          <span
            className={`hidden text-xs font-medium sm:inline ${
              step.key === currentStep ? 'text-foreground' : 'text-muted-foreground'
            }`}
          >
            {step.label}
          </span>
          {i < steps.length - 1 && <div className="mx-2 h-px w-8 bg-border sm:w-12" />}
        </div>
      ))}
    </div>
  )
}
