'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { Vault } from '@/lib/types'

export default function VaultsPage() {
  const [vaults, setVaults] = useState<Vault[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    api.listVaults().then(setVaults).catch(console.error)
  }, [])

  async function handleCreate() {
    if (!name.trim()) return
    setCreating(true)
    try {
      await api.createVault({ name, description })
      setShowCreate(false)
      setName('')
      setDescription('')
      api.listVaults().then(setVaults).catch(console.error)
    } catch {
      // error handled by API client
    } finally {
      setCreating(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Vaults</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Manage your MPC key vaults.
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Create Vault
          </button>
        </div>

        {/* Create vault dialog */}
        {showCreate && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
            <div className="w-full max-w-md rounded-lg border border-border bg-card p-6 shadow-lg">
              <h2 className="mb-4 text-lg font-semibold">Create Vault</h2>
              <div className="space-y-4">
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                    Name
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="Treasury Vault"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                    Description
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={3}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="Optional description"
                  />
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => setShowCreate(false)}
                    className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreate}
                    disabled={creating || !name.trim()}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
                  >
                    {creating ? 'Creating...' : 'Create'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Vault cards grid */}
        {vaults.length === 0 ? (
          <div className="rounded-lg border border-border bg-card p-12 text-center">
            <p className="text-muted-foreground">No vaults yet. Create one to get started.</p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {vaults.map((vault) => (
              <Link
                key={vault.id}
                href={`/vaults/${vault.id}`}
                className="group rounded-lg border border-border bg-card p-6 transition-colors hover:border-foreground/20"
              >
                <h3 className="font-semibold group-hover:text-foreground">
                  {vault.name}
                </h3>
                {vault.description && (
                  <p className="mt-1 text-sm text-muted-foreground line-clamp-2">
                    {vault.description}
                  </p>
                )}
                <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
                  <span>{new Date(vault.created_at).toLocaleDateString()}</span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </main>
    </>
  )
}
