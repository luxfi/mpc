'use client'

import { configureIam, logout, startLogin } from '@hanzo/iam/browser'
import { AppProvider, IdentityProvider } from '@luxfi/ui'
import { resolveWhiteLabel } from '@luxfi/ui/white-label'
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
// `IdentityProvider` reads the signed-in account and its org membership from
// IAM. Credentials stay with @hanzo/iam — one PKCE flow, one token store; the
// chrome borrows only the two verbs.
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
    const resolved = local && DEV_HOST ? DEV_HOST : real
    setHost(resolved)
    const wl = resolveWhiteLabel(resolved)
    configureIam({ issuer: wl.issuer, clientId: wl.clientId })
  }, [])

  return (
    <AppProvider host={host}>
      <IdentityProvider
        auth={{
          signIn: () => void startLogin({ redirect: '/dashboard' }),
          signOut: () => {
            clearTokens()
            void logout()
          },
        }}
      >
        {children}
      </IdentityProvider>
    </AppProvider>
  )
}
