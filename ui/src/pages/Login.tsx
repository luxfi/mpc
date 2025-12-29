import { useState, type FormEvent } from 'react'
import { useLocation } from 'wouter'
import { api, auth } from '../lib/api'
import { card, input, btn, label, h1, sub, errorText, disabledStyle } from '../lib/styles'

export function Login() {
  const [, navigate] = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfa, setMfa] = useState('')
  const [mfaRequired, setMfaRequired] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const r = await api.login(email, password, mfa || undefined)
      if (r.mfa_required) {
        setMfaRequired(true)
        return
      }
      auth.set(r.access_token, r.refresh_token, {
        id: r.user_id,
        org_id: r.org_id,
        role: r.role,
        email,
      })
      navigate('/')
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#000',
        color: '#e5e5e5',
        padding: 24,
      }}
    >
      <form onSubmit={onSubmit} style={{ ...card, width: 360 }}>
        <div style={{ ...h1, marginBottom: 4 }}>MPC Admin</div>
        <div style={sub}>Sign in to manage threshold wallets, policies, and operations.</div>

        <div style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <div style={label}>Email</div>
            <input
              style={{ ...input, marginTop: 4 }}
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={mfaRequired}
            />
          </div>
          <div>
            <div style={label}>Password</div>
            <input
              style={{ ...input, marginTop: 4 }}
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={mfaRequired}
            />
          </div>
          {mfaRequired && (
            <div>
              <div style={label}>MFA Code</div>
              <input
                style={{ ...input, marginTop: 4, fontFamily: 'monospace' }}
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                required
                autoFocus
                value={mfa}
                onChange={(e) => setMfa(e.target.value)}
              />
            </div>
          )}

          {err && <div style={errorText}>{err}</div>}

          <button
            type="submit"
            disabled={busy}
            style={{ ...btn, marginTop: 8, ...disabledStyle(busy) }}
          >
            {busy ? 'Signing in...' : mfaRequired ? 'Verify' : 'Sign in'}
          </button>
        </div>
      </form>
    </div>
  )
}
