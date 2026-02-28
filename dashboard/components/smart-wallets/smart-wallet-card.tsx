import Link from 'next/link'
import { StatusBadge } from '@/components/common/status-badge'

interface SmartWallet {
  id: string
  type: 'safe' | 'erc4337'
  chain: string
  chainId: number
  contractAddress: string
  threshold: number
  owners: string[]
  status: 'deployed' | 'pending' | 'failed'
}

interface SmartWalletCardProps {
  wallet: SmartWallet
}

export function SmartWalletCard({ wallet }: SmartWalletCardProps) {
  return (
    <Link
      href={`/smart-wallets/${wallet.id}`}
      className="group rounded-lg border border-border bg-card p-6 transition-colors hover:border-foreground/20"
    >
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold">
          {wallet.type === 'safe' ? 'Safe' : 'ERC-4337'}
        </span>
        <StatusBadge status={wallet.status === 'deployed' ? 'active' : wallet.status} />
      </div>
      <p className="mt-2 truncate font-mono text-xs text-muted-foreground">
        {wallet.contractAddress}
      </p>
      <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
        <span>
          {wallet.chain} ({wallet.chainId})
        </span>
        <span className="font-mono">
          {wallet.threshold}-of-{wallet.owners.length}
        </span>
      </div>
    </Link>
  )
}
