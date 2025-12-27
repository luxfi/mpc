'use client'

import { useState, useEffect, type FormEvent } from 'react'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { User } from '@/lib/types'

const roleBadgeColors: Record<string, string> = {
  owner: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  admin: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  signer: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  viewer: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
}

const roleOptions = ['admin', 'signer', 'viewer']

export default function TeamPage() {
  const [users, setUsers] = useState<User[]>([])
  const [error, setError] = useState('')

  // Invite form
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('signer')
  const [password, setPassword] = useState('')
  const [inviting, setInviting] = useState(false)

  // Inline edit
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editRole, setEditRole] = useState('')

  useEffect(() => {
    api.listUsers().then(setUsers).catch((e) => setError(e.message))
  }, [])

  async function handleInvite(e: FormEvent) {
    e.preventDefault()
    if (!email.trim() || !password.trim()) return
    setInviting(true)
    setError('')
    try {
      const user = await api.inviteUser({ email, role, password })
      setUsers((prev) => [...prev, user])
      setEmail('')
      setPassword('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to invite user')
    } finally {
      setInviting(false)
    }
  }

  async function handleUpdateRole(id: string) {
    setError('')
    try {
      const updated = await api.updateUser(id, { role: editRole })
      setUsers((prev) => prev.map((u) => (u.id === id ? updated : u)))
      setEditingId(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update role')
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteUser(id)
      setUsers((prev) => prev.filter((u) => u.id !== id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to remove user')
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Team</h1>
          <p className="mt-1 text-sm text-muted-foreground">Manage team members and their roles.</p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}

        {/* Invite form */}
        <form onSubmit={handleInvite} className="mb-8 rounded-lg border border-border bg-card p-6 space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Invite User</h2>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="user@example.com"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {roleOptions.map((r) => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-muted-foreground">Initial Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Temporary password"
              />
            </div>
          </div>
          <button
            type="submit"
            disabled={inviting || !email.trim() || !password.trim()}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {inviting ? 'Inviting...' : 'Invite'}
          </button>
        </form>

        {/* User table */}
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Email</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Role</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Joined</th>
                <th className="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-b border-border last:border-0">
                  <td className="px-4 py-3 font-medium">{user.email}</td>
                  <td className="px-4 py-3">
                    {editingId === user.id ? (
                      <div className="flex items-center gap-2">
                        <select
                          value={editRole}
                          onChange={(e) => setEditRole(e.target.value)}
                          className="rounded-md border border-input bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                        >
                          {roleOptions.map((r) => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                        <button
                          onClick={() => handleUpdateRole(user.id)}
                          className="text-xs text-primary hover:underline"
                        >
                          Save
                        </button>
                        <button
                          onClick={() => setEditingId(null)}
                          className="text-xs text-muted-foreground hover:underline"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize ${
                          roleBadgeColors[user.role] ?? 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
                        }`}
                      >
                        {user.role}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(user.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right space-x-3">
                    {editingId !== user.id && user.role !== 'owner' && (
                      <>
                        <button
                          onClick={() => { setEditingId(user.id); setEditRole(user.role) }}
                          className="text-sm text-muted-foreground hover:text-foreground"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(user.id)}
                          className="text-sm text-destructive hover:underline"
                        >
                          Remove
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                    No team members yet.
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
