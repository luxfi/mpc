'use client'

import { useState } from 'react'

export interface VaultFormProps {
  initialName?: string
  initialDescription?: string
  initialAppId?: string
  onSubmit: (data: { name: string; description: string; appId: string }) => void
  onCancel: () => void
  submitting?: boolean
}

export function VaultForm({
  initialName = '',
  initialDescription = '',
  initialAppId = '',
  onSubmit,
  onCancel,
  submitting = false,
}: VaultFormProps) {
  const [name, setName] = useState(initialName)
  const [description, setDescription] = useState(initialDescription)
  const [appId, setAppId] = useState(initialAppId)

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSubmit({ name, description, appId })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="vault-name">
          Name
        </label>
        <input
          id="vault-name"
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Vault name"
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="vault-desc">
          Description
        </label>
        <textarea
          id="vault-desc"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Optional description"
          rows={3}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor="vault-app-id">
          App ID
        </label>
        <input
          id="vault-app-id"
          type="text"
          value={appId}
          onChange={(e) => setAppId(e.target.value)}
          placeholder="Application identifier"
          className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
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
          {submitting ? 'Saving...' : 'Save'}
        </button>
      </div>
    </form>
  )
}
