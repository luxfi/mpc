'use client'

import { Suspense, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { setTokens, setUserEmail } from '@/lib/auth'
import { getBranding } from '@/lib/branding'
import { api } from '@/lib/api'

function CallbackInner() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState('Completing sign in…')

  useEffect(() => {
    // Check for error in query params (OAuth error redirects)
    const oauthError = searchParams.get('error')
    const oauthErrorDesc = searchParams.get('error_description')
    if (oauthError) {
      setError(oauthErrorDesc ?? oauthError)
      return
    }

    // Implicit flow: access_token may be in the hash fragment or query string
    // (Casdoor returns it in the query string, standard OAuth2 uses hash)
    const hash = window.location.hash.substring(1)
    const hashParams = new URLSearchParams(hash)
    const accessToken = hashParams.get('access_token') ?? searchParams.get('access_token')
    const state = hashParams.get('state') ?? searchParams.get('state')

    if (!accessToken) {
      setError('No access token received from identity provider')
      return
    }

    // Validate state to prevent CSRF
    const savedState = sessionStorage.getItem('oidc_state')
    if (savedState && state !== savedState) {
      setError('Invalid state parameter — possible CSRF attack')
      return
    }
    sessionStorage.removeItem('oidc_state')

    const branding = getBranding(window.location.hostname)

    setStatus('Authenticating with MPC API…')

    // Exchange the OIDC access token for a local MPC API JWT
    api
      .oidcExchange(accessToken, branding.iamUrl)
      .then((mpcAuth) => {
        setTokens(mpcAuth.access_token, mpcAuth.refresh_token)
        if (mpcAuth.email) {
          setUserEmail(mpcAuth.email)
        }
        router.replace('/dashboard')
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Authentication failed')
      })
  }, [searchParams, router])

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
      <CallbackInner />
    </Suspense>
  )
}
