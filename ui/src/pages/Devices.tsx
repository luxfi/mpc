import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useWebAuthnCredentials } from '../hooks/use-mpc'
import { api } from '../lib/api'
import { runWebAuthnRegister } from '../lib/webauthn'
import {
  card, label, btn, btnGhost,
  table, th, td, tHead, tRow, mono, h1, sub, errorText, disabledStyle, shorten,
} from '../lib/styles'

export function Devices() {
  const qc = useQueryClient()
  const { data: creds, error } = useWebAuthnCredentials()
  const [deviceName, setDeviceName] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [info, setInfo] = useState('')

  async function pair() {
    if (!deviceName.trim()) return
    setBusy(true); setErr(''); setInfo('')
    try {
      const opts = await api.webAuthnRegisterBegin()
      const completed = await runWebAuthnRegister(opts, deviceName.trim())
      const r = await api.webAuthnRegisterComplete(completed)
      setInfo(`Paired ${r.credential_id}`)
      setDeviceName('')
      qc.invalidateQueries({ queryKey: ['mpc', 'webauthn'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Pairing failed')
    } finally {
      setBusy(false)
    }
  }

  async function revoke(id: string) {
    setBusy(true); setErr('')
    try {
      await api.deleteWebAuthnCredential(id)
      qc.invalidateQueries({ queryKey: ['mpc', 'webauthn'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Revoke failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={h1}>Devices</h1>
        <p style={sub}>
          WebAuthn authenticators for biometric and hardware-key approval. Touch ID, Face ID, Windows Hello, YubiKey.
        </p>
      </div>

      {err && <div style={errorText}>{err}</div>}
      {info && <div style={{ color: '#22c55e', fontSize: 13 }}>{info}</div>}

      <div style={card}>
        <div style={{ ...label, marginBottom: 8 }}>Pair new device</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            placeholder="Device label (e.g. MacBook Touch ID)"
            value={deviceName}
            onChange={(e) => setDeviceName(e.target.value)}
            style={{
              flex: 1, minWidth: 240,
              background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
              padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
            }}
          />
          <button
            onClick={pair}
            disabled={busy || !deviceName.trim()}
            style={{ ...btn, ...disabledStyle(busy || !deviceName.trim()) }}
          >
            {busy ? 'Authenticating...' : 'Pair'}
          </button>
        </div>
        <div style={{ fontSize: 11, color: '#525252', marginTop: 8 }}>
          The browser will prompt your platform authenticator. Ensure user verification is available.
        </div>
      </div>

      {error && <div style={errorText}>{(error as Error).message}</div>}

      <table style={table}>
        <thead>
          <tr style={tHead}>
            <th style={th}>Device</th>
            <th style={th}>Credential ID</th>
            <th style={th}>Created</th>
            <th style={{ ...th, textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(creds ?? []).map((c) => (
            <tr key={c.id} style={tRow}>
              <td style={td}>{c.device_name ?? '--'}</td>
              <td style={{ ...td, ...mono, fontSize: 11 }}>{shorten(c.id, 10, 6)}</td>
              <td style={{ ...td, color: '#737373' }}>{new Date(c.created_at).toLocaleString()}</td>
              <td style={{ ...td, textAlign: 'right' }}>
                <button
                  onClick={() => revoke(c.id)}
                  disabled={busy}
                  style={{ ...btnGhost, padding: '4px 12px', ...disabledStyle(busy) }}
                >
                  Revoke
                </button>
              </td>
            </tr>
          ))}
          {(creds ?? []).length === 0 && (
            <tr>
              <td colSpan={4} style={{ ...td, color: '#525252' }}>
                No paired devices.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
