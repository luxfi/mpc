'use client'

import { useCallback } from 'react'

const IAM_URL = process.env.NEXT_PUBLIC_IAM_URL ?? 'https://lux.id'
const IAM_CLIENT_ID = process.env.NEXT_PUBLIC_IAM_CLIENT_ID ?? 'lux-mpc'
const CALLBACK_PATH = '/auth/callback'

function buildLoginUrl(): string {
  const redirectUri = `${window.location.origin}${CALLBACK_PATH}`
  const state = crypto.randomUUID()
  sessionStorage.setItem('oidc_state', state)

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: IAM_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
  })

  return `${IAM_URL}/login/oauth/authorize?${params.toString()}`
}

export default function LoginPage() {
  const handleLogin = useCallback(() => {
    window.location.href = buildLoginUrl()
  }, [])

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="rounded-lg border border-border bg-card p-8">
          <h1 className="mb-2 text-center text-xl font-semibold tracking-tight">
            Lux MPC
          </h1>
          <p className="mb-8 text-center text-sm text-muted-foreground">
            Multi-Party Computation Wallet Platform
          </p>

          <button
            type="button"
            onClick={handleLogin}
            className="w-full rounded-md bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Continue with Lux ID
          </button>

          <p className="mt-4 text-center text-xs text-muted-foreground">
            Powered by{' '}
            <a
              href="https://lux.id"
              target="_blank"
              rel="noreferrer"
              className="underline underline-offset-4 hover:text-foreground/80"
            >
              lux.id
            </a>
          </p>
        </div>
      </div>
    </div>
  )
}
