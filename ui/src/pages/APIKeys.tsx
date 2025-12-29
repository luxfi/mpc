import { useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAPIKeys } from '../hooks/use-mpc'
import { api } from '../lib/api'
import {
  card, label, btn, btnGhost, btnDanger,
  table, th, td, tHead, tRow, mono, h1, sub, errorText, disabledStyle,
} from '../lib/styles'

const presetPermissions = [
  'mpc:sign',
  'mpc:settlement:sign',
  'mpc:operations:approve',
  'mpc:wallet:sweep',
  'mpc:policy:write',
  'mpc:transactions:create',
  'mpc:subscriptions:write',
  'mpc:payment-requests:write',
  'mpc:smart-wallets:write',
  'mpc:trade:write',
  'mpc.treasury.admin',
  'mpc.treasury.sign',
  'sign',
  'trade:submit',
]

export function APIKeys() {
  const qc = useQueryClient()
  const { data: keys, error } = useAPIKeys()
  const [name, setName] = useState('')
  const [perms, setPerms] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [revealed, setRevealed] = useState<{ name: string; key: string } | null>(null)

  function toggle(p: string) {
    const n = new Set(perms)
    if (n.has(p)) n.delete(p); else n.add(p)
    setPerms(n)
  }

  async function create(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true); setErr('')
    try {
      const r = await api.createAPIKey({
        name: name.trim(),
        permissions: Array.from(perms),
      })
      setRevealed({ name: r.name, key: r.key })
      setName(''); setPerms(new Set())
      qc.invalidateQueries({ queryKey: ['mpc', 'api-keys'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Create failed')
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: string) {
    try {
      await api.deleteAPIKey(id)
      qc.invalidateQueries({ queryKey: ['mpc', 'api-keys'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Delete failed')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={h1}>API Keys</h1>
        <p style={sub}>
          Service-account credentials. Keys are shown once at creation; capture them then.
        </p>
      </div>

      {err && <div style={errorText}>{err}</div>}

      {revealed && (
        <div style={{ ...card, borderColor: '#22c55e' }}>
          <div style={{ ...label, color: '#22c55e' }}>Key created — copy now</div>
          <div style={{ marginTop: 4, fontSize: 13 }}>{revealed.name}</div>
          <div style={{ marginTop: 8, padding: 8, background: '#000', borderRadius: 4, ...mono, fontSize: 12, wordBreak: 'break-all' }}>
            {revealed.key}
          </div>
          <button
            onClick={() => setRevealed(null)}
            style={{ ...btnGhost, marginTop: 12, padding: '4px 12px' }}
          >
            Dismiss
          </button>
        </div>
      )}

      <form onSubmit={create} style={card}>
        <div style={{ ...label, marginBottom: 8 }}>New API key</div>
        <input
          placeholder="Key name (e.g. ats-service-account)"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{
            background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
            padding: '6px 12px', color: '#e5e5e5', fontSize: 13, width: '100%',
          }}
        />
        <div style={{ ...label, marginTop: 12 }}>Permissions (must enumerate; wildcard `*` is rejected)</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
          {presetPermissions.map((p) => {
            const on = perms.has(p)
            return (
              <button
                key={p}
                type="button"
                onClick={() => toggle(p)}
                style={{
                  ...btnGhost,
                  padding: '3px 10px', fontSize: 11, ...mono,
                  ...(on ? { background: '#22c55e20', color: '#22c55e', borderColor: '#22c55e' } : {}),
                }}
              >
                {p}
              </button>
            )
          })}
        </div>
        <button
          type="submit"
          disabled={busy || !name.trim() || perms.size === 0}
          style={{ ...btn, marginTop: 12, ...disabledStyle(busy || !name.trim() || perms.size === 0) }}
        >
          {busy ? 'Creating...' : 'Create key'}
        </button>
      </form>

      {error && <div style={errorText}>{(error as Error).message}</div>}

      <table style={table}>
        <thead>
          <tr style={tHead}>
            <th style={th}>Name</th>
            <th style={th}>Prefix</th>
            <th style={th}>Permissions</th>
            <th style={th}>Last used</th>
            <th style={th}>Created</th>
            <th style={{ ...th, textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(keys ?? []).map((k) => (
            <tr key={k.id} style={tRow}>
              <td style={td}>{k.name}</td>
              <td style={{ ...td, ...mono, fontSize: 11 }}>{k.keyPrefix}…</td>
              <td style={{ ...td, fontSize: 11, color: '#a3a3a3' }}>
                {k.permissions.length > 0 ? k.permissions.join(', ') : <span style={{ color: '#525252' }}>none</span>}
              </td>
              <td style={{ ...td, color: '#737373' }}>{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : '--'}</td>
              <td style={{ ...td, color: '#737373' }}>{new Date(k.createdAt).toLocaleString()}</td>
              <td style={{ ...td, textAlign: 'right' }}>
                <button
                  onClick={() => remove(k.id)}
                  style={{ ...btnDanger, padding: '4px 12px', background: 'transparent', color: '#ef4444', border: '1px solid #ef4444' }}
                >
                  Revoke
                </button>
              </td>
            </tr>
          ))}
          {(keys ?? []).length === 0 && (
            <tr>
              <td colSpan={6} style={{ ...td, color: '#525252' }}>
                No API keys.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
