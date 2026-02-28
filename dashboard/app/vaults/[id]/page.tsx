'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { DataTable, type Column } from '@/components/common/data-table'
import { StatusBadge } from '@/components/common/status-badge'
import { api } from '@/lib/api'
import type { Vault, Wallet } from '@/lib/types'

const columns: Column<Wallet>[] = [
  { key: 'name', header: 'Name', render: (row) => <span>{row.name || row.wallet_id.slice(0, 12)}</span> },
  { key: 'key_type', header: 'Type', render: (row) => <span className="font-mono text-xs">{row.key_type}</span> },
  {
    key: 'eth_address',
    header: 'Address',
    render: (row) => (
      <span className="font-mono text-xs">
        {row.eth_address ? `${row.eth_address.slice(0, 10)}...${row.eth_address.slice(-8)}` : '--'}
      </span>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) => <StatusBadge status={row.status} />,
  },
  {
    key: 'created_at',
    header: 'Created',
    render: (row) => <span className="text-muted-foreground">{new Date(row.created_at).toLocaleDateString()}</span>,
  },
]

export default function VaultDetailPage() {
  const params = useParams<{ id: string }>()
  const [vault, setVault] = useState<Vault | null>(null)
  const [wallets, setWallets] = useState<Wallet[]>([])

  useEffect(() => {
    if (!params.id) return
    api.getVault(params.id).then(setVault).catch(console.error)
    api.listWallets(params.id).then(setWallets).catch(console.error)
  }, [params.id])

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Vault header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
            <Link href="/vaults" className="hover:text-foreground">Vaults</Link>
            <span>/</span>
            <span>{vault?.name ?? 'Loading...'}</span>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">{vault?.name ?? 'Loading...'}</h1>
              {vault?.description && (
                <p className="mt-1 text-sm text-muted-foreground">{vault.description}</p>
              )}
              {vault?.app_id && (
                <p className="mt-1 text-xs text-muted-foreground font-mono">
                  App ID: {vault.app_id}
                </p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Link
                href={`/policies?vault=${params.id}`}
                className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent"
              >
                Policies
              </Link>
              <Link
                href={`/vaults/${params.id}/wallets/new`}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
              >
                Create Wallet
              </Link>
            </div>
          </div>
        </div>

        {/* Wallets table */}
        <h2 className="mb-4 text-lg font-semibold">Wallets</h2>
        <DataTable<Wallet>
          columns={columns}
          data={wallets}
          keyField="id"
          emptyMessage="No wallets in this vault yet."
        />
      </main>
    </>
  )
}
