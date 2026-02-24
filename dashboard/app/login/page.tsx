'use client'

import { useCallback, useState, useEffect } from 'react'
import { getBranding, type Branding } from '@/lib/branding'

const CALLBACK_PATH = '/auth/callback'

function buildLoginUrl(branding: Branding): string {
  const redirectUri = `${window.location.origin}${CALLBACK_PATH}`
  const state = crypto.randomUUID()
  sessionStorage.setItem('oidc_state', state)

  const params = new URLSearchParams({
    response_type: 'token',
    client_id: branding.iamClientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
  })

  return `${branding.iamUrl}/login?${params.toString()}`
}

export default function LoginPage() {
  const [branding, setBranding] = useState<Branding>(getBranding(''))
  useEffect(() => { setBranding(getBranding(window.location.hostname)) }, [])

  const handleLogin = useCallback(() => {
    window.location.href = buildLoginUrl(branding)
  }, [branding])

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="rounded-lg border border-border bg-card p-8">
          <h1 className="mb-2 text-center text-xl font-semibold tracking-tight">
            {branding.brand}
          </h1>
          <p className="mb-8 text-center text-sm text-muted-foreground">
            {branding.description}
          </p>

          <button
            type="button"
            onClick={handleLogin}
            className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Continue with {branding.iamLabel}
          </button>

          <p className="mt-4 text-center text-xs text-muted-foreground">
            Powered by{' '}
            <a
              href={branding.iamUrl}
              target="_blank"
              rel="noreferrer"
              className="underline underline-offset-4 hover:text-foreground/80"
            >
              {branding.iamLabel}
            </a>
          </p>
        </div>
      </div>
    </div>
  )
}
