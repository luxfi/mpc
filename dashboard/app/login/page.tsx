'use client'

import { startLogin } from '@hanzo/iam/browser'
import { useWhiteLabel } from '@luxfi/ui'
import { useCallback } from 'react'

// One button, one flow. The authorize URL, the PKCE challenge, the state nonce
// and the token exchange are all @hanzo/iam's — this page never reconstructs an
// IdP URL. (It used to: an implicit-grant `response_type=token` request built by
// hand against `${iamUrl}/oauth/authorize`, which is not even the issuer's
// authorize path — the real one is `/v1/iam/oauth/authorize`.)
//
// Brand, issuer and client id come from the host via `useWhiteLabel()`.
export default function LoginPage() {
  const wl = useWhiteLabel()
  const signIn = useCallback(() => {
    void startLogin({ redirect: '/dashboard' })
  }, [])

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="rounded-lg border border-border bg-card p-8">
          <h1 className="mb-2 text-center text-xl font-semibold tracking-tight">
            {wl.name} MPC
          </h1>
          <p className="mb-8 text-center text-sm text-muted-foreground">
            Multi-Party Computation wallet platform by {wl.name}
          </p>

          <button
            type="button"
            onClick={signIn}
            className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Continue with {wl.iamDomain}
          </button>

          <p className="mt-4 text-center text-xs text-muted-foreground">
            Powered by{' '}
            <a
              href={wl.issuer}
              target="_blank"
              rel="noreferrer"
              className="underline underline-offset-4 hover:text-foreground/80"
            >
              {wl.iamDomain}
            </a>
          </p>
        </div>
      </div>
    </div>
  )
}
