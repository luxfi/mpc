'use client'

import { useState } from 'react'

export interface ApprovalPanelProps {
  transactionId: string
  status: 'awaiting_approval' | 'pending' | 'confirmed' | 'failed'
  requiredApprovals: number
  currentApprovals: number
  canApprove: boolean
  onApprove: (transactionId: string) => Promise<void>
  onReject: (transactionId: string) => Promise<void>
}

export function ApprovalPanel({
  transactionId,
  status,
  requiredApprovals,
  currentApprovals,
  canApprove,
  onApprove,
  onReject,
}: ApprovalPanelProps) {
  const [acting, setActing] = useState(false)

  async function handleApprove() {
    setActing(true)
    try {
      await onApprove(transactionId)
    } finally {
      setActing(false)
    }
  }

  async function handleReject() {
    setActing(true)
    try {
      await onReject(transactionId)
    } finally {
      setActing(false)
    }
  }

  if (status !== 'awaiting_approval') {
    return null
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-4">
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">Approvals</span>
        <span className="font-mono">
          {currentApprovals} / {requiredApprovals}
        </span>
      </div>

      <div className="h-1.5 w-full rounded-full bg-muted">
        <div
          className="h-1.5 rounded-full bg-primary transition-all"
          style={{
            width: `${Math.min(100, (currentApprovals / requiredApprovals) * 100)}%`,
          }}
        />
      </div>

      {canApprove && (
        <div className="flex gap-3">
          <button
            onClick={handleReject}
            disabled={acting}
            className="flex-1 rounded-md border border-destructive/30 px-4 py-2 text-sm font-medium text-destructive hover:bg-destructive/10 disabled:opacity-50"
          >
            Reject
          </button>
          <button
            onClick={handleApprove}
            disabled={acting}
            className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {acting ? 'Submitting...' : 'Approve'}
          </button>
        </div>
      )}

      {!canApprove && (
        <p className="text-center text-xs text-muted-foreground">
          You have already submitted your approval for this transaction.
        </p>
      )}
    </div>
  )
}
