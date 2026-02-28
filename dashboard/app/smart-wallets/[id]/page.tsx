'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import { api, APIError } from '@/lib/api'
import { SafeTxQueue } from '@/components/smart-wallets/safe-tx-queue'
import { TxTable } from '@/components/transactions/tx-table'
import type { SmartWallet, Transaction } from '@/lib/types'

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

  const [wallet, setWallet] = useState<SmartWallet | null>(null)
  const [txHistory, setTxHistory] = useState<Transaction[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState('')

  // Pending Safe transactions (from wallet history with pending status)
  const [pendingTxs, setPendingTxs] = useState<PendingSafeTx[]>([])

  // Safe: propose new transaction
  const [proposeTo, setProposeTo] = useState('')
  const [proposeValue, setProposeValue] = useState('')
  const [proposeData, setProposeData] = useState('')
  const [proposeLoading, setProposeLoading] = useState(false)
  const [proposeError, setProposeError] = useState('')

  // ERC-4337: submit UserOperation
  const [userOpTarget, setUserOpTarget] = useState('')
  const [userOpValue, setUserOpValue] = useState('')
  const [userOpCalldata, setUserOpCalldata] = useState('')
  const [userOpLoading, setUserOpLoading] = useState(false)
  const [userOpError, setUserOpError] = useState('')

  useEffect(() => {
    async function fetchData() {
      try {
        const sw = await api.getSmartWallet(params.id)
        setWallet(sw)

        // Fetch transaction history for the parent MPC wallet
        try {
          const history = await api.getWalletHistory(sw.wallet_id)
          setTxHistory(history)

          // Derive pending Safe txs from pending transactions
          const pending: PendingSafeTx[] = history
            .filter((tx) => tx.status === 'pending' || tx.status === 'pending_approval')
            .map((tx, i) => ({
              id: tx.id,
              to: tx.to_address ?? '',
              value: tx.amount ?? '0',
              data: '0x',
              nonce: i,
              confirmations: tx.approved_by?.length ?? 0,
              required: sw.threshold,
              submittedBy: tx.initiated_by ?? 'unknown',
              createdAt: tx.created_at,
            }))
          setPendingTxs(pending)
        } catch {
          // tx history fetch failed, non-fatal
        }
      } catch (err) {
        setFetchError(err instanceof APIError ? err.message : 'Failed to load smart wallet')
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [params.id])

  async function handleProposeSafeTx() {
    if (!wallet) return
    setProposeLoading(true)
    setProposeError('')
    try {
      await api.proposeSafeTx(params.id, {
        to: proposeTo,
        value: proposeValue,
        data: proposeData || undefined,
      })
      setProposeTo('')
      setProposeValue('')
      setProposeData('')
      // Refresh wallet data
      const history = await api.getWalletHistory(wallet.wallet_id).catch(() => [])
      setTxHistory(history)
    } catch (err) {
      setProposeError(err instanceof APIError ? err.message : 'Failed to propose transaction')
    } finally {
      setProposeLoading(false)
    }
  }

  async function handleSubmitUserOp() {
    if (!wallet) return
    setUserOpLoading(true)
    setUserOpError('')
    try {
      await api.userOperation(params.id, {
        call_data: userOpCalldata,
        value: userOpValue || undefined,
      })
      setUserOpTarget('')
      setUserOpValue('')
      setUserOpCalldata('')
    } catch (err) {
      setUserOpError(err instanceof APIError ? err.message : 'Failed to submit UserOperation')
    } finally {
      setUserOpLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl px-4 py-8">
        <p className="text-sm text-muted-foreground">Loading smart wallet...</p>
      </div>
    )
  }

  if (fetchError || !wallet) {
    return (
      <div className="mx-auto max-w-4xl px-4 py-8">
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {fetchError || 'Smart wallet not found'}
        </div>
      </div>
    )
  }

  // Map API transactions to TxTable format
  const tableTransactions = txHistory.map((tx) => ({
    id: tx.id,
    type: tx.tx_type,
    status: (tx.status === 'pending_approval' ? 'awaiting_approval' : tx.status) as
      'pending' | 'confirmed' | 'failed' | 'awaiting_approval',
    chain: tx.chain,
    from: wallet.contract_address,
    to: tx.to_address ?? '',
    value: tx.amount ?? '0',
    hash: tx.tx_hash ?? undefined,
    timestamp: tx.created_at,
  }))

  return (
    <div className="mx-auto max-w-4xl space-y-8 px-4 py-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          {wallet.wallet_type === 'safe' ? 'Safe' : 'ERC-4337'} Wallet
        </h1>
        <p className="mt-1 truncate font-mono text-sm text-muted-foreground">
          {wallet.contract_address}
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
              {wallet.wallet_type === 'safe' ? 'Gnosis Safe' : 'ERC-4337 Account'}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Chain</dt>
            <dd className="mt-1">{wallet.chain}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Threshold</dt>
            <dd className="mt-1 font-mono">
              {wallet.threshold}-of-{wallet.owners.length}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">MPC Wallet</dt>
            <dd className="mt-1 font-mono text-xs">{wallet.wallet_id}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Status</dt>
            <dd className="mt-1 capitalize">{wallet.status}</dd>
          </div>
          {wallet.deployed_at && (
            <div>
              <dt className="text-muted-foreground">Deployed</dt>
              <dd className="mt-1 text-xs">{new Date(wallet.deployed_at).toLocaleString()}</dd>
            </div>
          )}
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
      {wallet.wallet_type === 'safe' && (
        <>
          <section className="space-y-4">
            <h2 className="text-lg font-semibold">Pending Transactions</h2>
            <SafeTxQueue transactions={pendingTxs} walletId={wallet.id} />
          </section>

          <section className="rounded-lg border border-border bg-card p-6 space-y-4">
            <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
              Propose Transaction
            </h2>
            {proposeError && (
              <p className="text-sm text-destructive">{proposeError}</p>
            )}
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
                disabled={!proposeTo || proposeLoading}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {proposeLoading ? 'Proposing...' : 'Propose Transaction'}
              </button>
            </div>
          </section>
        </>
      )}

      {/* ERC-4337: UserOperation */}
      {wallet.wallet_type === 'erc4337' && (
        <section className="rounded-lg border border-border bg-card p-6 space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
            Submit UserOperation
          </h2>
          {userOpError && (
            <p className="text-sm text-destructive">{userOpError}</p>
          )}
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
              disabled={!userOpTarget || userOpLoading}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {userOpLoading ? 'Submitting...' : 'Submit UserOperation'}
            </button>
          </div>
        </section>
      )}

      {/* Transaction history */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold">Transaction History</h2>
        <TxTable transactions={tableTransactions} />
      </section>
    </div>
  )
}
