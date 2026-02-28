'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'
import type { InfoResponse } from '@/lib/types'

const settingsLinks = [
  {
    href: '/settings/api-keys' as const,
    title: 'API Keys',
    description: 'Manage API keys for programmatic access.',
  },
  {
    href: '/settings/webhooks' as const,
    title: 'Webhooks',
    description: 'Configure webhook endpoints for event notifications.',
  },
]

export default function SettingsPage() {
  const [info, setInfo] = useState<InfoResponse | null>(null)

  useEffect(() => {
    api.getInfo().then(setInfo).catch(() => {})
  }, [])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
          <p className="mt-1 text-sm text-muted-foreground">Organization settings and integrations.</p>
        </div>

        {/* Org info */}
        <div className="mb-8 rounded-lg border border-border bg-card p-6">
          <h2 className="mb-4 text-lg font-semibold">Organization</h2>
          <dl className="grid gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-xs text-muted-foreground">Service</dt>
              <dd className="mt-1 text-sm font-medium">{info?.name || '--'}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Version</dt>
              <dd className="mt-1 font-mono text-sm">{info?.version || '--'}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Supported Chains</dt>
              <dd className="mt-1 text-sm">
                {info?.supported_chains?.join(', ') || '--'}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Key Types</dt>
              <dd className="mt-1 font-mono text-sm">
                {info?.key_types?.join(', ') || '--'}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Protocols</dt>
              <dd className="mt-1 text-sm">
                {info?.protocols?.join(', ') || '--'}
              </dd>
            </div>
          </dl>
        </div>

        {/* Sub-pages */}
        <div className="grid gap-4 sm:grid-cols-2">
          {settingsLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="group rounded-lg border border-border bg-card p-6 transition-colors hover:border-foreground/20"
            >
              <h3 className="font-semibold group-hover:text-foreground">{link.title}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{link.description}</p>
            </Link>
          ))}
        </div>
      </main>
    </>
  )
}
