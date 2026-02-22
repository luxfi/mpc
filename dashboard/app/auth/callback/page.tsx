'use client'

import { Suspense, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { setTokens, setUserEmail } from '@/lib/auth'
import { getBranding } from '@/lib/branding'
import { api } from '@/lib/api'

function OidcCallbackInner() {
  const router = useRouter()
  const params = useSearchParams()
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState('Completing sign in…')

  useEffect(() => {
    const code = params.get('code')
    const state = params.get('state')
    const oauthError = params.get('error')
    const oauthErrorDesc = params.get('error_description')

    if (oauthError) {
      setError(oauthErrorDesc ?? oauthError)
      return
    }

    if (!code) return

    const savedState = sessionStorage.getItem('oidc_state')
    if (savedState && state !== savedState) {
      setError('Invalid state parameter — possible CSRF attack')
      return
    }
    sessionStorage.removeItem('oidc_state')

    const branding = getBranding(window.location.hostname)
    const redirectUri = `${window.location.origin}/auth/callback`

    setStatus('Exchanging authorization code…')

    // Step 1: Exchange code for Lux ID access token
    fetch(`${branding.iamUrl}/api/login/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: branding.iamClientId,
      }),
    })
      .then(async (res) => {
        if (!res.ok) {
          const body = await res.text()
          throw new Error(`Token exchange failed: ${body}`)
        }
        return res.json() as Promise<{
          access_token: string
          refresh_token?: string
        }>
      })
      .then(async (oidcData) => {
        setStatus('Authenticating with MPC API…')

        // Step 2: Exchange the OIDC token for a local MPC API JWT
        const mpcAuth = await api.oidcExchange(oidcData.access_token, branding.iamUrl)

        // Store the MPC API tokens (NOT the Lux ID token)
        setTokens(mpcAuth.access_token, mpcAuth.refresh_token)
        if (mpcAuth.email) {
          setUserEmail(mpcAuth.email)
        }

        router.replace('/dashboard')
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Authentication failed')
      })
  }, [params, router])

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center px-4">
        <div className="w-full max-w-sm rounded-lg border border-border bg-card p-8 text-center">
          <p className="mb-2 text-lg font-semibold text-destructive">Authentication Error</p>
          <p className="mb-6 text-sm text-muted-foreground">{error}</p>
          <a
            href="/login"
            className="text-sm underline underline-offset-4 hover:text-foreground/80"
          >
            Try again
          </a>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm text-center">
        <p className="text-sm text-muted-foreground">{status}</p>
      </div>
    </div>
  )
}

export default function OidcCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center px-4">
          <div className="w-full max-w-sm text-center">
            <p className="text-sm text-muted-foreground">Loading…</p>
          </div>
        </div>
      }
    >
      <OidcCallbackInner />
    </Suspense>
  )
}
