'use client'

import { AppProvider } from '@luxfi/ui'
import { AuthProvider } from '@luxfi/ui/auth'
import { useEffect, useState, type ReactNode } from 'react'

import { clearTokens } from '@/lib/auth'

// The root providers: brand + identity, both resolved from the HOST.
//
// `AppProvider` (@luxfi/ui) carries the white-label — brand, gui theme row,
// OIDC issuer and IAM client id all come from the Host header, so one image
// serves mpc.lux.network, mpc.zoo.network and mpc.pars.network with no
// per-deployment branding table. It also owns the QueryClient, so there is one
// query cache per surface instead of one per provider file.
//
// `AuthProvider` (@luxfi/ui/auth) is the identity read AND the PKCE login,
// bound to that same host. This file used to hand-roll the credential half —
// `configureIam` + `startLogin` + `logout` — and so did lux/market, while
// lux/explore hand-built an authorize URL with no PKCE at all. One flow now
// lives in the design system; a surface names only where a session lands and
// what of its OWN it drops on the way out.
//
// NEXT_PUBLIC_HOST is the LOCAL-DEV seam and nothing else: `localhost` has no
// brand to resolve, so a developer names the host the surface stands in for.
// It is unset in every deployment, where the real Host header answers.
const DEV_HOST = process.env.NEXT_PUBLIC_HOST

export function Providers({ children }: { children: ReactNode }) {
  const [host, setHost] = useState<string | undefined>(undefined)

  useEffect(() => {
    const real = window.location.host
    const local = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(real)
    setHost(local && DEV_HOST ? DEV_HOST : real)
  }, [])

  return (
    <AppProvider host={host}>
      <AuthProvider redirect="/dashboard" onSignOut={clearTokens}>
        {children}
      </AuthProvider>
    </AppProvider>
  )
}
