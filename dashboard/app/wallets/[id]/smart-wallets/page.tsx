'use client'

import { useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { SmartWalletCard } from '@/components/smart-wallets/smart-wallet-card'

export interface SmartWallet {
  id: string
  type: 'safe' | 'erc4337'
  chain: string
  chainId: number
  contractAddress: string
  threshold: number
  owners: string[]
  status: 'deployed' | 'pending' | 'failed'
}

export default function SmartWalletsPage() {
  const params = useParams<{ id: string }>()

  // TODO: fetch smart wallets from API
  const [wallets] = useState<SmartWallet[]>([
    {
      id: 'sw-1',
      type: 'safe',
      chain: 'Ethereum',
      chainId: 1,
      contractAddress: '0x1234...abcd',
      threshold: 2,
      owners: ['0xaaa...111', '0xbbb...222', '0xccc...333'],
      status: 'deployed',
    },
    {
      id: 'sw-2',
      type: 'erc4337',
      chain: 'Lux C-Chain',
      chainId: 96369,
      contractAddress: '0x5678...efgh',
      threshold: 1,
      owners: ['0xaaa...111'],
      status: 'deployed',
    },
  ])

  return (
    <div className="mx-auto max-w-4xl space-y-8 px-4 py-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Smart Wallets
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Smart contract wallets backed by MPC key{' '}
            <span className="font-mono">{params.id}</span>
          </p>
        </div>
        <Link
          href={`/wallets/${params.id}/smart-wallets/deploy`}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Deploy Smart Wallet
        </Link>
      </div>

      {wallets.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-12 text-center">
          <p className="text-muted-foreground">
            No smart wallets deployed yet.
          </p>
          <Link
            href={`/wallets/${params.id}/smart-wallets/deploy`}
            className="mt-4 inline-block text-sm font-medium text-primary hover:underline"
          >
            Deploy your first smart wallet
          </Link>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {wallets.map((sw) => (
            <SmartWalletCard key={sw.id} wallet={sw} />
          ))}
        </div>
      )}
    </div>
  )
}
