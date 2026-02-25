'use client'

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import { isWebAuthnSupported, startRegistration } from '@/lib/webauthn'

export default function DevicesPage() {
  const [credentials, setCredentials] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [registering, setRegistering] = useState(false)
  const [deviceName, setDeviceName] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const supported = isWebAuthnSupported()

  const loadCreds = useCallback(async () => {
    try {
      setLoading(true)
      const creds = await api.listWebAuthnCredentials()
      setCredentials(creds)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadCreds() }, [loadCreds])

  async function handleRegister() {
    if (!supported) return
    setRegistering(true)
    setError('')
    setSuccess('')
    try {
      const options = await api.webauthnRegisterBegin()
      const result = await startRegistration(options)
      result.device_name = deviceName || 'My Device'
      await api.webauthnRegisterComplete(result)
      setDeviceName('')
      setSuccess('Device registered successfully')
      await loadCreds()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setRegistering(false)
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteWebAuthnCredential(id)
      await loadCreds()
    } catch (e: any) {
      setError(e.message)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/settings" className="hover:text-foreground">Settings</Link>
          <span>/</span>
          <span>Devices & Biometrics</span>
        </div>

        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Devices & Biometrics</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Register Face ID, Touch ID, or YubiKey to approve transactions with biometrics.
          </p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}
        {success && <p className="mb-4 text-sm text-green-500">{success}</p>}

        {!supported && (
          <div className="mb-8 rounded-lg border border-border bg-card p-6 text-center">
            <p className="text-muted-foreground">
              WebAuthn is not supported in this browser. Use Chrome, Safari, Firefox, or Edge.
            </p>
          </div>
        )}

        {supported && (
          <div className="mb-8 rounded-lg border border-border bg-card p-6">
            <h2 className="mb-4 text-lg font-semibold">Register New Device</h2>
            <div className="flex items-end gap-4">
              <div className="flex-1">
                <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                  Device Name
                </label>
                <input
                  type="text"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="e.g., MacBook Pro Touch ID"
                />
              </div>
              <button
                onClick={handleRegister}
                disabled={registering}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
              >
                {registering ? 'Waiting for biometric...' : 'Register Device'}
              </button>
            </div>
          </div>
        )}

        {loading ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : credentials.length === 0 ? (
          <div className="rounded-lg border border-border bg-card p-12 text-center">
            <p className="text-muted-foreground">No devices registered yet.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {credentials.map((cred) => (
              <div
                key={cred.id}
                className="flex items-center justify-between rounded-lg border border-border bg-card px-6 py-4"
              >
                <div>
                  <p className="text-sm font-medium">{cred.device_name || 'Unnamed device'}</p>
                  <p className="mt-1 font-mono text-xs text-muted-foreground">{cred.id.slice(0, 16)}...</p>
                </div>
                <button
                  onClick={() => handleDelete(cred.id)}
                  className="rounded-md border border-destructive/30 px-3 py-1.5 text-xs font-medium text-destructive hover:bg-destructive/10"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </main>
    </>
  )
}
