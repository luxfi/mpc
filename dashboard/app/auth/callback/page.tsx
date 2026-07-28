'use client'

import { useWhiteLabel } from '@luxfi/ui'
import { AuthCallback } from '@luxfi/ui/auth'
import { useRouter } from 'next/navigation'
import { Suspense } from 'react'
import { markSession, setTokens, setUserEmail } from '@/lib/auth'
import { api } from '@/lib/api'

// The OAuth callback route, at the ONE path every Lux browser client registers:
// https://<host>/auth/callback.
//
// The state check, the PKCE verifier and the code→token exchange are
// `@luxfi/ui/auth`'s (which is `@hanzo/iam`'s). This page says only what MPC
// does with a fresh session. It used to restate the exchange, the error card
// and the spinner — as did lux/explore's callback, over a DIFFERENT and
// PKCE-less exchange.
function CallbackInner() {
  const router = useRouter()
  const wl = useWhiteLabel()

  return (
    <AuthCallback
      navigate={(to) => router.replace(to)}
      fallback="/dashboard"
      onSignedIn={async ({ token }) => {
        // The middleware cannot see sessionStorage; raise its flag the moment
        // the IAM login succeeds, so the gate follows the SESSION and not the
        // downstream MPC exchange below.
        markSession(true)

        // The MPC API keeps its OWN JWT, minted from the IAM token. That
        // exchange is DOWNSTREAM: if the API is unreachable the user is still
        // signed in and the chrome still works — MPC data is what fails, and
        // it says so on the page that needs it. Throwing here does not fail
        // the login (AuthCallback absorbs it), which is what used to strand a
        // perfectly good session on this screen.
        const mpc = await api.oidcExchange(token.accessToken, wl.issuer)
        setTokens(mpc.access_token, mpc.refresh_token)
        if (mpc.email) setUserEmail(mpc.email)
      }}
    />
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
