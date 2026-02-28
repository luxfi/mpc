'use client'

import { useState } from 'react'

export type PolicyType = 'spend_limit' | 'whitelist' | 'time_lock' | 'quorum' | 'custom'

export interface PolicyCondition {
  field: string
  operator: string
  value: string
}

export interface PolicyFormData {
  name: string
  type: PolicyType
  conditions: PolicyCondition[]
  appliedTo: string
}

export interface PolicyFormProps {
  initialData?: Partial<PolicyFormData>
  onSubmit: (data: PolicyFormData) => void
  onCancel: () => void
  submitting?: boolean
}

const policyTypes: { value: PolicyType; label: string }[] = [
  { value: 'spend_limit', label: 'Spend Limit' },
  { value: 'whitelist', label: 'Whitelist' },
  { value: 'time_lock', label: 'Time Lock' },
  { value: 'quorum', label: 'Quorum' },
  { value: 'custom', label: 'Custom' },
]

const operators = ['==', '!=', '>', '<', '>=', '<=', 'in', 'not_in']

const conditionFields: Record<PolicyType, string[]> = {
  spend_limit: ['amount', 'token', 'period'],
  whitelist: ['to_address', 'chain'],
  time_lock: ['delay_seconds', 'window_start', 'window_end'],
  quorum: ['required_approvals', 'approver_group'],
  custom: ['field'],
}

export function PolicyForm({
  initialData,
  onSubmit,
  onCancel,
  submitting = false,
}: PolicyFormProps) {
  const [name, setName] = useState(initialData?.name ?? '')
  const [type, setType] = useState<PolicyType>(initialData?.type ?? 'spend_limit')
  const [conditions, setConditions] = useState<PolicyCondition[]>(
    initialData?.conditions ?? [{ field: '', operator: '==', value: '' }]
  )
  const [appliedTo, setAppliedTo] = useState(initialData?.appliedTo ?? '')

  function addCondition() {
    setConditions((c) => [...c, { field: '', operator: '==', value: '' }])
  }

  function updateCondition(index: number, patch: Partial<PolicyCondition>) {
    setConditions((c) =>
      c.map((cond, i) => (i === index ? { ...cond, ...patch } : cond))
    )
  }

  function removeCondition(index: number) {
    setConditions((c) => c.filter((_, i) => i !== index))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSubmit({ name, type, conditions, appliedTo })
  }

  const fields = conditionFields[type]

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="policy-name">
          Policy Name
        </label>
        <input
          id="policy-name"
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Daily Spend Limit"
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="policy-type">
          Type
        </label>
        <select
          id="policy-type"
          value={type}
          onChange={(e) => setType(e.target.value as PolicyType)}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        >
          {policyTypes.map((pt) => (
            <option key={pt.value} value={pt.value}>
              {pt.label}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="policy-applied">
          Applied To (wallet or vault ID)
        </label>
        <input
          id="policy-applied"
          type="text"
          value={appliedTo}
          onChange={(e) => setAppliedTo(e.target.value)}
          placeholder="wallet-... or vault-... or * for all"
          className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium">Conditions</label>
          <button
            type="button"
            onClick={addCondition}
            className="text-sm font-medium text-primary hover:underline"
          >
            + Add Condition
          </button>
        </div>

        {conditions.map((cond, i) => (
          <div key={i} className="flex items-start gap-2">
            <select
              value={cond.field}
              onChange={(e) => updateCondition(i, { field: e.target.value })}
              className="w-1/3 rounded-md border border-input bg-background px-2 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="">Field...</option>
              {fields.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>

            <select
              value={cond.operator}
              onChange={(e) => updateCondition(i, { operator: e.target.value })}
              className="w-24 rounded-md border border-input bg-background px-2 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {operators.map((op) => (
                <option key={op} value={op}>
                  {op}
                </option>
              ))}
            </select>

            <input
              type="text"
              value={cond.value}
              onChange={(e) => updateCondition(i, { value: e.target.value })}
              placeholder="Value"
              className="flex-1 rounded-md border border-input bg-background px-2 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />

            {conditions.length > 1 && (
              <button
                type="button"
                onClick={() => removeCondition(i)}
                className="rounded-md border border-border px-2 py-2 text-sm text-muted-foreground hover:bg-accent"
              >
                Remove
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="flex gap-3 pt-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={submitting}
          className="flex-1 rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting || !name}
          className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {submitting ? 'Saving...' : 'Save Policy'}
        </button>
      </div>
    </form>
  )
}
