'use client'

import { useMemo, useSyncExternalStore } from 'react'

export interface Branding {
  brand: string
  logoText: string
  description: string
}

export const brandingConfig: Record<string, Branding> = {
  'mpc.lux.network': {
    brand: 'Lux MPC',
    logoText: 'Lux MPC',
    description: 'Multi-Party Computation Wallet Platform by Lux Network',
  },
  'cloud.lux.network': {
    brand: 'Lux Cloud',
    logoText: 'Lux Cloud',
    description: 'Cloud Wallet Management by Lux Network',
  },
}

const defaultBranding: Branding = brandingConfig['mpc.lux.network']

/** Pure function for server-side use. Pass the hostname from request headers. */
export function getBranding(hostname: string): Branding {
  // Strip port if present (e.g. localhost:3000 -> localhost)
  const host = hostname.split(':')[0]
  return brandingConfig[host] ?? defaultBranding
}

// Subscribe to nothing -- hostname doesn't change during a session.
function subscribe() {
  return () => {}
}

function getHostname() {
  return typeof window !== 'undefined' ? window.location.hostname : ''
}

function getServerHostname() {
  return ''
}

/** Client hook. Reads window.location.hostname once and returns branding. */
export function useBranding(): Branding {
  const hostname = useSyncExternalStore(subscribe, getHostname, getServerHostname)
  return useMemo(() => getBranding(hostname), [hostname])
}
