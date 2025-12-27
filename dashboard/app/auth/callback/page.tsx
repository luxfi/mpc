'use client'

import { Suspense, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { setTokens } from '@/lib/auth'

const IAM_URL = process.env.NEXT_PUBLIC_IAM_URL ?? 'https://lux.id'
const IAM_CLIENT_ID = process.env.NEXT_PUBLIC_IAM_CLIENT_ID ?? 'lux-mpc'

function OidcCallbackInner() {
  const router = useRouter()
  const params = useSearchParams()
  const [error, setError] = useState<string | null>(null)

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

    const redirectUri = `${window.location.origin}/auth/callback`

    fetch(`${IAM_URL}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: IAM_CLIENT_ID,
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
      .then((data) => {
        setTokens(data.access_token, data.refresh_token ?? '')
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
        <p className="text-sm text-muted-foreground">Completing sign in…</p>
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
