'use client'

import { AppNav } from '@luxfi/ui'
import { usePathname } from 'next/navigation'

// The nav is the ONE nav — brand, org switcher, links, settings, user menu —
// from @luxfi/ui. It used to be a bespoke header with a bespoke user menu and
// `hidden md:flex` links that simply vanished on a phone with nothing to
// replace them; the shared chrome collapses them into the same gui Sheet the
// switchers use, so mobile is a real presentation rather than an omission.
const LINKS = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/vaults', label: 'Vaults' },
  { href: '/transactions', label: 'Transactions' },
  { href: '/intents', label: 'Intents' },
  { href: '/settlements', label: 'Settlements' },
  { href: '/policies', label: 'Policies' },
  { href: '/bridge', label: 'Bridge' },
  { href: '/team', label: 'Team' },
] as const

export function Nav() {
  const pathname = usePathname()
  return (
    <AppNav
      home="/dashboard"
      links={LINKS.map((l) => ({ ...l, active: pathname.startsWith(l.href) }))}
      settings={[
        { id: 'api-keys', label: 'API keys', href: '/settings/api-keys' },
        { id: 'webhooks', label: 'Webhooks', href: '/settings/webhooks' },
        { id: 'devices', label: 'Devices', href: '/settings/devices' },
      ]}
      userItems={[{ id: 'audit', label: 'Audit log', href: '/audit' }]}
    />
  )
}
