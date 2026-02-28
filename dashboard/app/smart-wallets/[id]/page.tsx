'use client'

import { useState } from 'react'
import { useParams } from 'next/navigation'
import { SafeTxQueue } from '@/components/smart-wallets/safe-tx-queue'
import { TxTable } from '@/components/transactions/tx-table'

interface SmartWalletDetail {
  id: string
  type: 'safe' | 'erc4337'
  chain: string
  chainId: number
  contractAddress: string
  threshold: number
  owners: string[]
  mpcWalletId: string
}

interface PendingSafeTx {
  id: string
  to: string
  value: string
  data: string
  nonce: number
  confirmations: number
  required: number
  submittedBy: string
  createdAt: string
}

export default function SmartWalletDetailPage() {
  const params = useParams<{ id: string }>()

  // TODO: fetch from API
  const [wallet] = useState<SmartWalletDetail>({
    id: params.id,
    type: 'safe',
    chain: 'Ethereum',
    chainId: 1,
    contractAddress: '0x1234567890abcdef1234567890abcdef12345678',
    threshold: 2,
    owners: [
      '0xaaa1111111111111111111111111111111111111',
      '0xbbb2222222222222222222222222222222222222',
      '0xccc3333333333333333333333333333333333333',
    ],
    mpcWalletId: 'wallet-abc',
  })

  const [pendingTxs] = useState<PendingSafeTx[]>([
    {
      id: 'stx-1',
      to: '0xddd4444444444444444444444444444444444444',
      value: '1.5 ETH',
      data: '0x',
      nonce: 0,
      confirmations: 1,
      required: 2,
      submittedBy: '0xaaa...111',
      createdAt: '2026-02-28T10:00:00Z',
    },
  ])

  // Safe: propose new transaction
  const [proposeTo, setProposeTo] = useState('')
  const [proposeValue, setProposeValue] = useState('')
  const [proposeData, setProposeData] = useState('')

  // ERC-4337: submit UserOperation
  const [userOpTarget, setUserOpTarget] = useState('')
  const [userOpValue, setUserOpValue] = useState('')
  const [userOpCalldata, setUserOpCalldata] = useState('')

  async function handleProposeSafeTx() {
    // TODO: call API to propose Safe transaction
    alert(`Propose tx to ${proposeTo} for ${proposeValue}`)
  }

  async function handleSubmitUserOp() {
    // TODO: call API to submit UserOperation
    alert(`Submit UserOp to ${userOpTarget} for ${userOpValue}`)
  }

  return (
    <div className="mx-auto max-w-4xl space-y-8 px-4 py-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          {wallet.type === 'safe' ? 'Safe' : 'ERC-4337'} Wallet
        </h1>
        <p className="mt-1 truncate font-mono text-sm text-muted-foreground">
          {wallet.contractAddress}
        </p>
      </div>

      {/* Contract info */}
      <section className="rounded-lg border border-border bg-card p-6 space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
          Contract Info
        </h2>
        <dl className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <dt className="text-muted-foreground">Type</dt>
            <dd className="mt-1">
              {wallet.type === 'safe' ? 'Gnosis Safe' : 'ERC-4337 Account'}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Chain</dt>
            <dd className="mt-1">
              {wallet.chain} ({wallet.chainId})
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Threshold</dt>
            <dd className="mt-1 font-mono">
              {wallet.threshold}-of-{wallet.owners.length}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">MPC Wallet</dt>
            <dd className="mt-1 font-mono text-xs">{wallet.mpcWalletId}</dd>
          </div>
          <div className="col-span-2">
            <dt className="text-muted-foreground">Owners</dt>
            <dd className="mt-1 space-y-1">
              {wallet.owners.map((o) => (
                <p key={o} className="truncate font-mono text-xs">
                  {o}
                </p>
              ))}
            </dd>
          </div>
        </dl>
      </section>

      {/* Safe: pending transactions */}
      {wallet.type === 'safe' && (
        <>
          <section className="space-y-4">
            <h2 className="text-lg font-semibold">Pending Transactions</h2>
            <SafeTxQueue transactions={pendingTxs} walletId={wallet.id} />
          </section>

          <section className="rounded-lg border border-border bg-card p-6 space-y-4">
            <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
              Propose Transaction
            </h2>
            <div className="space-y-3">
              <input
                type="text"
                value={proposeTo}
                onChange={(e) => setProposeTo(e.target.value)}
                placeholder="Recipient address (0x...)"
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              />
              <input
                type="text"
                value={proposeValue}
                onChange={(e) => setProposeValue(e.target.value)}
                placeholder="Value (e.g. 1.0)"
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              />
              <textarea
                value={proposeData}
                onChange={(e) => setProposeData(e.target.value)}
                placeholder="Calldata (0x... or leave empty)"
                rows={3}
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              />
              <button
                onClick={handleProposeSafeTx}
                disabled={!proposeTo}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                Propose Transaction
              </button>
            </div>
          </section>
        </>
      )}

      {/* ERC-4337: UserOperation */}
      {wallet.type === 'erc4337' && (
        <section className="rounded-lg border border-border bg-card p-6 space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
            Submit UserOperation
          </h2>
          <div className="space-y-3">
            <input
              type="text"
              value={userOpTarget}
              onChange={(e) => setUserOpTarget(e.target.value)}
              placeholder="Target address (0x...)"
              className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <input
              type="text"
              value={userOpValue}
              onChange={(e) => setUserOpValue(e.target.value)}
              placeholder="Value (e.g. 1.0)"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <textarea
              value={userOpCalldata}
              onChange={(e) => setUserOpCalldata(e.target.value)}
              placeholder="Calldata (0x...)"
              rows={3}
              className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <button
              onClick={handleSubmitUserOp}
              disabled={!userOpTarget}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              Submit UserOperation
            </button>
          </div>
        </section>
      )}

      {/* Transaction history */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold">Transaction History</h2>
        <TxTable
          transactions={[
            {
              id: 'tx-1',
              type: 'send',
              status: 'confirmed',
              chain: wallet.chain,
              from: wallet.contractAddress,
              to: '0xddd...444',
              value: '0.5 ETH',
              hash: '0xabc...123',
              timestamp: '2026-02-27T15:30:00Z',
            },
          ]}
        />
      </section>
    </div>
  )
}
