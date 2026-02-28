'use client'

import Link from 'next/link'

export interface VaultCardProps {
  id: string
  name: string
  description: string
  walletCount: number
}

export function VaultCard({ id, name, description, walletCount }: VaultCardProps) {
  return (
    <Link
      href={`/vaults/${id}`}
      className="block rounded-lg border border-border bg-card p-6 transition-colors hover:border-muted-foreground/30 hover:bg-accent/50"
    >
      <h3 className="text-sm font-semibold">{name}</h3>
      {description && (
        <p className="mt-1 text-xs text-muted-foreground line-clamp-2">
          {description}
        </p>
      )}
      <p className="mt-3 text-xs text-muted-foreground">
        {walletCount} wallet{walletCount !== 1 ? 's' : ''}
      </p>
    </Link>
  )
}
