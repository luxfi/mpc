'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { UserMenu } from './user-menu'

const navLinks = [
  { href: '/' as const, label: 'Dashboard' },
  { href: '/vaults' as const, label: 'Vaults' },
  { href: '/transactions' as const, label: 'Transactions' },
  { href: '/policies' as const, label: 'Policies' },
  { href: '/team' as const, label: 'Team' },
  { href: '/settings' as const, label: 'Settings' },
]

export function Nav() {
  const pathname = usePathname()

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <div className="flex items-center gap-8">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-lg font-semibold tracking-tight">Lux MPC</span>
          </Link>
          <nav className="hidden items-center gap-1 md:flex">
            {navLinks.map((link) => {
              const isActive =
                link.href === '/'
                  ? pathname === '/'
                  : pathname.startsWith(link.href)
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-accent text-accent-foreground'
                      : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                  }`}
                >
                  {link.label}
                </Link>
              )
            })}
          </nav>
        </div>
        <UserMenu />
      </div>
    </header>
  )
}
