import { useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useWebhooks } from '../hooks/use-mpc'
import { api } from '../lib/api'
import { StatusBadge } from '../components/StatusBadge'
import {
  card, label, btn, btnGhost,
  table, th, td, tHead, tRow, mono, h1, sub, errorText, disabledStyle,
} from '../lib/styles'

const eventOptions = [
  'transaction.created',
  'transaction.signed',
  'transaction.broadcast',
  'transaction.confirmed',
  'transaction.failed',
  'operation.pending_approval',
  'operation.approved',
  'operation.rejected',
  'wallet.created',
  'policy.violation',
  'session.created',
  'session.revoked',
]

export function Webhooks() {
  const qc = useQueryClient()
  const { data: webhooks, error } = useWebhooks()
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [events, setEvents] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [info, setInfo] = useState('')

  function toggle(e: string) {
    const n = new Set(events)
    if (n.has(e)) n.delete(e); else n.add(e)
    setEvents(n)
  }

  async function create(e: FormEvent) {
    e.preventDefault()
    if (!url.trim() || !secret.trim() || events.size === 0) return
    setBusy(true); setErr(''); setInfo('')
    try {
      await api.createWebhook({
        url: url.trim(),
        secret: secret.trim(),
        events: Array.from(events),
      })
      setUrl(''); setSecret(''); setEvents(new Set())
      qc.invalidateQueries({ queryKey: ['mpc', 'webhooks'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Create failed')
    } finally {
      setBusy(false)
    }
  }

  async function toggleEnabled(id: string, enabled: boolean) {
    try {
      await api.updateWebhook(id, { enabled: !enabled })
      qc.invalidateQueries({ queryKey: ['mpc', 'webhooks'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Update failed')
    }
  }

  async function test(id: string) {
    try {
      const r = await api.testWebhook(id)
      setInfo(`Test sent: ${r.status}`)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Test failed')
    }
  }

  async function remove(id: string) {
    try {
      await api.deleteWebhook(id)
      qc.invalidateQueries({ queryKey: ['mpc', 'webhooks'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Delete failed')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={h1}>Webhooks</h1>
        <p style={sub}>
          Outbound HTTP delivery of MPC events. Each request is HMAC-signed with the webhook secret.
        </p>
      </div>

      {err && <div style={errorText}>{err}</div>}
      {info && <div style={{ color: '#22c55e', fontSize: 13 }}>{info}</div>}

      <form onSubmit={create} style={card}>
        <div style={{ ...label, marginBottom: 8 }}>New webhook</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <input
            placeholder="https://example.com/webhook"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
            }}
          />
          <input
            placeholder="Shared HMAC secret"
            required
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13, ...mono,
            }}
          />
        </div>
        <div style={{ ...label, marginTop: 12 }}>Events</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
          {eventOptions.map((ev) => {
            const on = events.has(ev)
            return (
              <button
                key={ev}
                type="button"
                onClick={() => toggle(ev)}
                style={{
                  ...btnGhost, padding: '3px 10px', fontSize: 11, ...mono,
                  ...(on ? { background: '#3b82f620', color: '#3b82f6', borderColor: '#3b82f6' } : {}),
                }}
              >
                {ev}
              </button>
            )
          })}
        </div>
        <button
          type="submit"
          disabled={busy || !url.trim() || !secret.trim() || events.size === 0}
          style={{
            ...btn, marginTop: 12,
            ...disabledStyle(busy || !url.trim() || !secret.trim() || events.size === 0),
          }}
        >
          {busy ? 'Creating...' : 'Create webhook'}
        </button>
      </form>

      {error && <div style={errorText}>{(error as Error).message}</div>}

      <table style={table}>
        <thead>
          <tr style={tHead}>
            <th style={th}>URL</th>
            <th style={th}>Events</th>
            <th style={th}>Status</th>
            <th style={th}>Created</th>
            <th style={{ ...th, textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(webhooks ?? []).map((w) => (
            <tr key={w.id} style={tRow}>
              <td style={{ ...td, ...mono, fontSize: 11 }}>{w.url}</td>
              <td style={{ ...td, fontSize: 11, color: '#a3a3a3' }}>{w.events.join(', ')}</td>
              <td style={td}><StatusBadge status={w.enabled ? 'enabled' : 'disabled'} /></td>
              <td style={{ ...td, color: '#737373' }}>{new Date(w.created_at).toLocaleString()}</td>
              <td style={{ ...td, textAlign: 'right' }}>
                <button onClick={() => test(w.id)} style={{ ...btnGhost, padding: '3px 10px', marginRight: 4 }}>Test</button>
                <button onClick={() => toggleEnabled(w.id, w.enabled)} style={{ ...btnGhost, padding: '3px 10px', marginRight: 4 }}>
                  {w.enabled ? 'Disable' : 'Enable'}
                </button>
                <button onClick={() => remove(w.id)} style={{ ...btnGhost, padding: '3px 10px', color: '#ef4444', borderColor: '#ef4444' }}>
                  Delete
                </button>
              </td>
            </tr>
          ))}
          {(webhooks ?? []).length === 0 && (
            <tr>
              <td colSpan={5} style={{ ...td, color: '#525252' }}>
                No webhooks configured.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
