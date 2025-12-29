import { useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useUsers } from '../hooks/use-mpc'
import { api, auth } from '../lib/api'
import {
  card, label, btn, btnGhost,
  table, th, td, tHead, tRow, mono, h1, sub, errorText, disabledStyle, shorten,
} from '../lib/styles'

const roles = ['viewer', 'signer', 'admin', 'owner']

export function Users() {
  const qc = useQueryClient()
  const { data: users, error } = useUsers()
  const me = auth.user()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function invite(e: FormEvent) {
    e.preventDefault()
    if (!email.trim() || !password) return
    setBusy(true); setErr('')
    try {
      await api.inviteUser({ email: email.trim(), password, role })
      setEmail(''); setPassword(''); setRole('viewer')
      qc.invalidateQueries({ queryKey: ['mpc', 'users'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Invite failed')
    } finally {
      setBusy(false)
    }
  }

  async function changeRole(id: string, newRole: string) {
    try {
      await api.updateUser(id, { role: newRole })
      qc.invalidateQueries({ queryKey: ['mpc', 'users'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Update failed')
    }
  }

  async function remove(id: string) {
    try {
      await api.deleteUser(id)
      qc.invalidateQueries({ queryKey: ['mpc', 'users'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Delete failed')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={h1}>Users</h1>
        <p style={sub}>
          Org members with role-based permissions. Roles: viewer, signer, admin, owner.
        </p>
      </div>

      {err && <div style={errorText}>{err}</div>}

      <form onSubmit={invite} style={card}>
        <div style={{ ...label, marginBottom: 8 }}>Invite user</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 200px 140px auto', gap: 8 }}>
          <input
            type="email"
            placeholder="email@example.com"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
            }}
          />
          <input
            type="password"
            placeholder="Initial password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
            }}
          />
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
            }}
          >
            {roles.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <button
            type="submit"
            disabled={busy || !email.trim() || !password}
            style={{ ...btn, ...disabledStyle(busy || !email.trim() || !password) }}
          >
            {busy ? 'Inviting...' : 'Invite'}
          </button>
        </div>
      </form>

      {error && <div style={errorText}>{(error as Error).message}</div>}

      <table style={table}>
        <thead>
          <tr style={tHead}>
            <th style={th}>Email</th>
            <th style={th}>Role</th>
            <th style={th}>ID</th>
            <th style={th}>Created</th>
            <th style={{ ...th, textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(users ?? []).map((u) => {
            const isMe = me?.id === u.id
            return (
              <tr key={u.id} style={tRow}>
                <td style={td}>
                  {u.email} {isMe && <span style={{ fontSize: 11, color: '#22c55e', marginLeft: 4 }}>(you)</span>}
                </td>
                <td style={td}>
                  <select
                    value={u.role}
                    onChange={(e) => changeRole(u.id, e.target.value)}
                    disabled={isMe}
                    style={{
                      background: '#0a0a0a', border: '1px solid #262626', borderRadius: 4,
                      padding: '2px 8px', color: '#e5e5e5', fontSize: 12,
                    }}
                  >
                    {roles.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </td>
                <td style={{ ...td, ...mono, fontSize: 11 }}>{shorten(u.id, 10, 4)}</td>
                <td style={{ ...td, color: '#737373' }}>{new Date(u.createdAt).toLocaleString()}</td>
                <td style={{ ...td, textAlign: 'right' }}>
                  <button
                    onClick={() => remove(u.id)}
                    disabled={isMe}
                    style={{
                      ...btnGhost, padding: '3px 10px', color: '#ef4444', borderColor: '#ef4444',
                      ...disabledStyle(isMe),
                    }}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            )
          })}
          {(users ?? []).length === 0 && (
            <tr>
              <td colSpan={5} style={{ ...td, color: '#525252' }}>
                No users.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
