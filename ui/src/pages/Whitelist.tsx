import { useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useWhitelist } from '../hooks/use-mpc'
import { api } from '../lib/api'
import {
  card, label, btn, btnGhost,
  table, th, td, tHead, tRow, mono, h1, sub, errorText, disabledStyle,
} from '../lib/styles'

const chains = ['ethereum', 'bitcoin', 'lux', 'solana', 'polygon', 'arbitrum', 'base', 'optimism']

export function Whitelist() {
  const qc = useQueryClient()
  const { data: entries, error } = useWhitelist()
  const [address, setAddress] = useState('')
  const [chain, setChain] = useState('ethereum')
  const [labelText, setLabelText] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function add(e: FormEvent) {
    e.preventDefault()
    if (!address.trim()) return
    setBusy(true); setErr('')
    try {
      await api.addWhitelist({
        address: address.trim(),
        chain,
        label: labelText.trim() || undefined,
      })
      setAddress(''); setLabelText('')
      qc.invalidateQueries({ queryKey: ['mpc', 'whitelist'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Add failed')
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: string) {
    try {
      await api.deleteWhitelist(id)
      qc.invalidateQueries({ queryKey: ['mpc', 'whitelist'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Remove failed')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={h1}>Allowlist</h1>
        <p style={sub}>
          Permit destination addresses that policies can require for transfers.
        </p>
      </div>

      {err && <div style={errorText}>{err}</div>}

      <form onSubmit={add} style={card}>
        <div style={{ ...label, marginBottom: 8 }}>Add destination</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px 200px auto', gap: 8 }}>
          <input
            placeholder="Address"
            required
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13, fontFamily: 'monospace',
            }}
          />
          <select
            value={chain}
            onChange={(e) => setChain(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
            }}
          >
            {chains.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <input
            placeholder="Label (optional)"
            value={labelText}
            onChange={(e) => setLabelText(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
            }}
          />
          <button
            type="submit"
            disabled={busy || !address.trim()}
            style={{ ...btn, ...disabledStyle(busy || !address.trim()) }}
          >
            {busy ? 'Adding...' : 'Add'}
          </button>
        </div>
      </form>

      {error && <div style={errorText}>{(error as Error).message}</div>}

      <table style={table}>
        <thead>
          <tr style={tHead}>
            <th style={th}>Address</th>
            <th style={th}>Chain</th>
            <th style={th}>Label</th>
            <th style={th}>Created</th>
            <th style={{ ...th, textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(entries ?? []).map((e) => (
            <tr key={e.id} style={tRow}>
              <td style={{ ...td, ...mono, fontSize: 11 }}>{e.address}</td>
              <td style={td}>{e.chain}</td>
              <td style={td}>{e.label || '--'}</td>
              <td style={{ ...td, color: '#737373' }}>{new Date(e.created_at).toLocaleString()}</td>
              <td style={{ ...td, textAlign: 'right' }}>
                <button
                  onClick={() => remove(e.id)}
                  style={{ ...btnGhost, padding: '4px 12px' }}
                >
                  Remove
                </button>
              </td>
            </tr>
          ))}
          {(entries ?? []).length === 0 && (
            <tr>
              <td colSpan={5} style={{ ...td, color: '#525252' }}>
                No allowlisted destinations.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
