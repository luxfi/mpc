'use client'

import { useState, useEffect, type FormEvent } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Webhook } from '@/lib/types'

const eventOptions = [
  'transaction.created',
  'transaction.approved',
  'transaction.signed',
  'transaction.broadcast',
  'transaction.failed',
  'wallet.created',
  'wallet.reshared',
  'policy.triggered',
]

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [error, setError] = useState('')

  // Create form
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [selectedEvents, setSelectedEvents] = useState<string[]>([])
  const [creating, setCreating] = useState(false)
  const [testing, setTesting] = useState<string | null>(null)

  useEffect(() => {
    api.listWebhooks().then(setWebhooks).catch((e) => setError(e.message))
  }, [])

  function toggleEvent(event: string) {
    setSelectedEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    )
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    if (!url.trim() || selectedEvents.length === 0 || !secret.trim()) return
    setCreating(true)
    setError('')
    try {
      const webhook = await api.createWebhook({ url, events: selectedEvents, secret })
      setWebhooks((prev) => [webhook, ...prev])
      setUrl('')
      setSecret('')
      setSelectedEvents([])
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create webhook')
    } finally {
      setCreating(false)
    }
  }

  async function handleTest(id: string) {
    setTesting(id)
    setError('')
    try {
      await api.testWebhook(id)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Test failed')
    } finally {
      setTesting(null)
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteWebhook(id)
      setWebhooks((prev) => prev.filter((w) => w.id !== id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete webhook')
    }
  }

  async function handleToggle(id: string, enabled: boolean) {
    try {
      const updated = await api.updateWebhook(id, { enabled: !enabled })
      setWebhooks((prev) => prev.map((w) => (w.id === id ? updated : w)))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update webhook')
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-2 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/settings" className="hover:text-foreground">Settings</Link>
          <span>/</span>
          <span>Webhooks</span>
        </div>

        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Webhooks</h1>
          <p className="mt-1 text-sm text-muted-foreground">Receive event notifications via HTTP callbacks.</p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        {/* Create form */}
        <form onSubmit={handleCreate} className="mb-8 rounded-lg border border-border bg-card p-6 space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Create Webhook</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">URL</label>
              <input
                type="url"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="https://api.example.com/webhook"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Secret</label>
              <input
                type="text"
                required
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="whsec_..."
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-sm font-medium text-muted-foreground">Events</label>
            <div className="flex flex-wrap gap-3">
              {eventOptions.map((event) => (
                <label key={event} className="flex items-center gap-1.5">
                  <input
                    type="checkbox"
                    checked={selectedEvents.includes(event)}
                    onChange={() => toggleEvent(event)}
                    className="rounded border-input"
                  />
                  <span className="text-sm">{event}</span>
                </label>
              ))}
            </div>
          </div>
          <button
            type="submit"
            disabled={creating || !url.trim() || selectedEvents.length === 0 || !secret.trim()}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {creating ? 'Creating...' : 'Create Webhook'}
          </button>
        </form>

        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">URL</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Events</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map((wh) => (
                <tr key={wh.id} className="border-b border-border last:border-0">
                  <td className="px-4 py-3 font-mono text-xs break-all max-w-[300px]">{wh.url}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {wh.events.map((ev) => (
                        <span key={ev} className="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                          {ev}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={wh.enabled ? 'active' : 'disabled'} />
                  </td>
                  <td className="px-4 py-3 text-right space-x-3">
                    <button
                      onClick={() => handleTest(wh.id)}
                      disabled={testing === wh.id}
                      className="text-sm text-muted-foreground hover:text-foreground disabled:opacity-50"
                    >
                      {testing === wh.id ? 'Testing...' : 'Test'}
                    </button>
                    <button
                      onClick={() => handleToggle(wh.id, wh.enabled)}
                      className="text-sm text-muted-foreground hover:text-foreground"
                    >
                      {wh.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      onClick={() => handleDelete(wh.id)}
                      className="text-sm text-destructive hover:underline"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {webhooks.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                    No webhooks configured.
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
