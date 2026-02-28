'use client'

import Link from 'next/link'

export interface WalletCardProps {
  id: string
  name: string
  threshold: number
  participants: number
  ecdsaPubkey: string
  eddsaPubkey?: string
  protocol: 'cggmp21' | 'frost' | 'lss'
  createdAt: string
}

export function WalletCard({
  id,
  name,
  threshold,
  participants,
  ecdsaPubkey,
  eddsaPubkey,
  protocol,
  createdAt,
}: WalletCardProps) {
  const protocolLabel: Record<string, string> = {
    cggmp21: 'CGGMP21',
    frost: 'FROST',
    lss: 'LSS',
  }

  return (
    <Link
      href={`/wallets/${id}`}
      className="block rounded-lg border border-border bg-card p-6 transition-colors hover:border-muted-foreground/30 hover:bg-accent/50"
    >
      <div className="flex items-start justify-between">
        <h3 className="text-sm font-semibold">{name}</h3>
        <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
          {protocolLabel[protocol] ?? protocol}
        </span>
      </div>

      <p className="mt-2 font-mono text-xs text-muted-foreground">
        {threshold}-of-{participants}
      </p>

      <div className="mt-3 space-y-1">
        <p className="truncate font-mono text-xs text-muted-foreground" title={ecdsaPubkey}>
          ECDSA: {ecdsaPubkey}
        </p>
        {eddsaPubkey && (
          <p className="truncate font-mono text-xs text-muted-foreground" title={eddsaPubkey}>
            EdDSA: {eddsaPubkey}
          </p>
        )}
      </div>

      <p className="mt-3 text-xs text-muted-foreground">
        Created {new Date(createdAt).toLocaleDateString()}
      </p>
    </Link>
  )
}
