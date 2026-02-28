'use client'

import { useState, useEffect, type FormEvent } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { APIKey, APIKeyCreateResponse } from '@/lib/types'

const permissionOptions = ['read', 'write', 'sign', 'admin']

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([])
  const [error, setError] = useState('')

  // Create form
  const [name, setName] = useState('')
  const [permissions, setPermissions] = useState<string[]>(['read'])
  const [creating, setCreating] = useState(false)
  const [newKey, setNewKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    api.listAPIKeys().then(setKeys).catch((e) => setError(e.message))
  }, [])

  function togglePermission(perm: string) {
    setPermissions((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]
    )
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    setError('')
    try {
      const result: APIKeyCreateResponse = await api.createAPIKey({ name, permissions })
      setNewKey(result.key)
      setKeys((prev) => [result, ...prev])
      setName('')
      setPermissions(['read'])
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create key')
    } finally {
      setCreating(false)
    }
  }

  function handleCopy() {
    if (newKey) {
      navigator.clipboard.writeText(newKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteAPIKey(id)
      setKeys((prev) => prev.filter((k) => k.id !== id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete key')
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-2 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/settings" className="hover:text-foreground">Settings</Link>
          <span>/</span>
          <span>API Keys</span>
        </div>

        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">API Keys</h1>
          <p className="mt-1 text-sm text-muted-foreground">Manage programmatic access keys.</p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        {/* Created key banner */}
        {newKey && (
          <div className="mb-6 rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
            <p className="mb-2 text-sm font-medium text-amber-400">
              API key created. Copy it now -- it will not be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-md bg-muted p-2 font-mono text-xs">{newKey}</code>
              <button
                onClick={handleCopy}
                className="shrink-0 rounded-md border border-border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-accent"
              >
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <button
              onClick={() => setNewKey(null)}
              className="mt-2 text-xs text-muted-foreground hover:text-foreground"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Create form */}
        <form onSubmit={handleCreate} className="mb-8 rounded-lg border border-border bg-card p-6 space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Create Key</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Production API key"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Permissions</label>
              <div className="flex flex-wrap gap-3">
                {permissionOptions.map((perm) => (
                  <label key={perm} className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={permissions.includes(perm)}
                      onChange={() => togglePermission(perm)}
                      className="rounded border-input"
                    />
                    <span className="text-sm capitalize">{perm}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
          <button
            type="submit"
            disabled={creating || !name.trim()}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {creating ? 'Creating...' : 'Create Key'}
          </button>
        </form>

        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Name</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Key Prefix</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Created</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Last Used</th>
                <th className="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id} className="border-b border-border last:border-0">
                  <td className="px-4 py-3 font-medium">{key.name}</td>
                  <td className="px-4 py-3 font-mono text-xs">{key.key_prefix}...</td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(key.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDelete(key.id)}
                      className="text-sm text-destructive hover:underline"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
              {keys.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                    No API keys created.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </main>
    </>
  )
}
