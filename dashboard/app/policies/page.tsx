'use client'

import { useState, useEffect, type FormEvent } from 'react'
import { Nav } from '@/components/layout/nav'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Policy } from '@/lib/types'

const actionOptions = ['approve', 'deny', 'require_approval']

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [error, setError] = useState('')

  // Create form state
  const [name, setName] = useState('')
  const [action, setAction] = useState('require_approval')
  const [priority, setPriority] = useState(0)
  const [requiredApprovers, setRequiredApprovers] = useState(1)
  const [approverRoles, setApproverRoles] = useState('admin,owner')
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    api.listPolicies().then(setPolicies).catch((e) => setError(e.message))
  }, [])

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    setCreating(true)
    setError('')
    try {
      const policy = await api.createPolicy({
        name,
        action,
        priority,
        conditions: {},
        required_approvers: requiredApprovers,
        approver_roles: approverRoles.split(',').map((r) => r.trim()).filter(Boolean),
      })
      setPolicies((prev) => [policy, ...prev])
      setName('')
      setPriority(0)
      setRequiredApprovers(1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create policy')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deletePolicy(id)
      setPolicies((prev) => prev.filter((p) => p.id !== id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete policy')
    }
  }

  async function handleToggle(id: string, enabled: boolean) {
    try {
      const updated = await api.updatePolicy(id, { enabled: !enabled })
      setPolicies((prev) => prev.map((p) => (p.id === id ? updated : p)))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update policy')
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Policies</h1>
          <p className="mt-1 text-sm text-muted-foreground">Configure signing policies and approval rules.</p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        {/* Inline create form */}
        <form onSubmit={handleCreate} className="mb-8 rounded-lg border border-border bg-card p-6 space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Create Policy</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Daily spend limit"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Action</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {actionOptions.map((a) => (
                  <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Priority</label>
              <input
                type="number"
                value={priority}
                onChange={(e) => setPriority(Number(e.target.value))}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Required Approvers</label>
              <input
                type="number"
                min={1}
                value={requiredApprovers}
                onChange={(e) => setRequiredApprovers(Number(e.target.value))}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-sm font-medium text-muted-foreground">Approver Roles (comma-separated)</label>
            <input
              type="text"
              value={approverRoles}
              onChange={(e) => setApproverRoles(e.target.value)}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="admin,owner"
            />
          </div>
          <button
            type="submit"
            disabled={creating || !name.trim()}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {creating ? 'Creating...' : 'Create Policy'}
          </button>
        </form>

        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Name</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Action</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Priority</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className="border-b border-border last:border-0">
                  <td className="px-4 py-3 font-medium">{p.name}</td>
                  <td className="px-4 py-3 capitalize">{p.action.replace(/_/g, ' ')}</td>
                  <td className="px-4 py-3 font-mono">{p.priority}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={p.enabled ? 'enabled' : 'disabled'} />
                  </td>
                  <td className="px-4 py-3 text-right space-x-3">
                    <button
                      onClick={() => handleToggle(p.id, p.enabled)}
                      className="text-sm text-muted-foreground hover:text-foreground"
                    >
                      {p.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      onClick={() => handleDelete(p.id)}
                      className="text-sm text-destructive hover:underline"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {policies.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                    No policies configured.
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
