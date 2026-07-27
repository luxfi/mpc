'use client'

import { handleCallback } from '@hanzo/iam/browser'
import { useWhiteLabel } from '@luxfi/ui'
import { useRouter } from 'next/navigation'
import { Suspense, useEffect, useState } from 'react'
import { markSession, setTokens, setUserEmail } from '@/lib/auth'
import { api } from '@/lib/api'

function CallbackInner() {
  const router = useRouter()
  const wl = useWhiteLabel()
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState('Completing sign in…')

  useEffect(() => {
    let live = true
    void (async () => {
      try {
        // ONE exchange: state check + PKCE verifier + code→token, all inside
        // the SDK. The IAM access token IS the session from here on, stored
        // under the `hanzo_iam_*` keys the shared chrome reads.
        const { token, redirect } = await handleCallback()
        if (!live) return
        // The middleware cannot see sessionStorage; raise its flag the moment
        // the IAM login succeeds, so the gate follows the SESSION and not the
        // downstream MPC exchange below.
        markSession(true)

        // The MPC API keeps its OWN JWT, minted from the IAM token. That
        // exchange is a DOWNSTREAM call: if the API is unreachable the user is
        // still signed in and the chrome still works — MPC data is what fails,
        // and it says so on the page that needs it. Failing the whole login for
        // it used to strand a perfectly good session on this screen.
        setStatus('Authenticating with the MPC API…')
        try {
          const mpc = await api.oidcExchange(token.accessToken, wl.issuer)
          setTokens(mpc.access_token, mpc.refresh_token)
          if (mpc.email) setUserEmail(mpc.email)
        } catch {
          // Signed in; MPC API unavailable.
        }
        if (live) router.replace(redirect || '/dashboard')
      } catch (err: unknown) {
        if (live) setError(err instanceof Error ? err.message : 'Authentication failed')
      }
    })()
    return () => {
      live = false
    }
  }, [router, wl.issuer])

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
