'use client'

import { useState, useEffect, type FormEvent } from 'react'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { AddressWhitelist } from '@/lib/types'

const chains = ['ethereum', 'bitcoin', 'lux', 'solana', 'xrpl', 'zoo', 'hanzo']

export default function WhitelistPage() {
  const [entries, setEntries] = useState<AddressWhitelist[]>([])
  const [error, setError] = useState('')

  // Form state
  const [newAddress, setNewAddress] = useState('')
  const [newChain, setNewChain] = useState(chains[0])
  const [newLabel, setNewLabel] = useState('')
  const [adding, setAdding] = useState(false)

  useEffect(() => {
    api.listWhitelist().then(setEntries).catch((e) => setError(e.message))
  }, [])

  async function handleAdd(e: FormEvent) {
    e.preventDefault()
    setAdding(true)
    setError('')
    try {
      const entry = await api.addWhitelist({
        address: newAddress,
        chain: newChain,
        label: newLabel || undefined,
      })
      setEntries((prev) => [entry, ...prev])
      setNewAddress('')
      setNewLabel('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add address')
    } finally {
      setAdding(false)
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteWhitelist(id)
      setEntries((prev) => prev.filter((e) => e.id !== id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete')
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Address Whitelist</h1>
          <p className="mt-1 text-sm text-muted-foreground">Manage approved addresses for outgoing transactions.</p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        {/* Add form */}
        <form onSubmit={handleAdd} className="mb-8 rounded-lg border border-border bg-card p-6 space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Add Address</h2>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="sm:col-span-2 space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Address</label>
              <input
                type="text"
                required
                value={newAddress}
                onChange={(e) => setNewAddress(e.target.value)}
                placeholder="0x..."
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Chain</label>
              <select
                value={newChain}
                onChange={(e) => setNewChain(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {chains.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-sm font-medium text-muted-foreground">Label</label>
            <input
              type="text"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="e.g. Treasury, Exchange, Partner"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <button
            type="submit"
            disabled={adding || !newAddress}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {adding ? 'Adding...' : 'Add to Whitelist'}
          </button>
        </form>

        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Address</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Chain</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Label</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Added By</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Date</th>
                <th className="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id} className="border-b border-border last:border-0">
                  <td className="px-4 py-3 font-mono text-xs">
                    <span className="block max-w-[200px] truncate">{entry.address}</span>
                  </td>
                  <td className="px-4 py-3 capitalize">{entry.chain}</td>
                  <td className="px-4 py-3">{entry.label || '--'}</td>
                  <td className="px-4 py-3 text-muted-foreground font-mono text-xs">
                    {entry.created_by || '--'}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(entry.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDelete(entry.id)}
                      className="text-sm text-destructive hover:underline"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {entries.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    No whitelisted addresses yet.
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
