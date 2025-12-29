import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useOperations } from '../hooks/use-mpc'
import { api, type Operation } from '../lib/api'
import { StatusBadge } from '../components/StatusBadge'
import {
  card, label, btn, btnGhost, btnDanger,
  table, th, td, tHead, tRow, mono, h1, sub, errorText, disabledStyle, shorten,
} from '../lib/styles'

const statusFilters = [
  { v: '', l: 'All' },
  { v: 'pending_approval', l: 'Pending approval' },
  { v: 'approved', l: 'Approved' },
  { v: 'signed', l: 'Signed' },
  { v: 'rejected', l: 'Rejected' },
  { v: 'failed', l: 'Failed' },
  { v: 'expired', l: 'Expired' },
]

export function Operations() {
  const [status, setStatus] = useState('pending_approval')
  const [page, setPage] = useState(1)
  const filters = { status: status || undefined, page, perPage: 25 }
  const { data, error } = useOperations(filters)
  const [selected, setSelected] = useState<Operation | null>(null)

  const items = data?.items ?? []
  const total = data?.totalItems ?? 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={h1}>Operations</h1>
        <p style={sub}>
          Approval inbox. Pending intents need your signature; approved ones are signing now.
        </p>
      </div>

      {error && <div style={errorText}>{(error as Error).message}</div>}

      {/* Filter bar */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        {statusFilters.map((f) => (
          <button
            key={f.v}
            onClick={() => { setStatus(f.v); setPage(1) }}
            style={{
              ...btnGhost,
              padding: '4px 12px',
              fontSize: 12,
              ...(status === f.v ? { background: '#fff', color: '#000', border: '1px solid #fff' } : {}),
            }}
          >
            {f.l}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', fontSize: 12, color: '#737373' }}>
          {total} total
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selected ? 'minmax(0, 1fr) 420px' : '1fr', gap: 16 }}>
        {/* Table */}
        <div>
          <table style={table}>
            <thead>
              <tr style={tHead}>
                <th style={th}>Op ID</th>
                <th style={th}>Kind</th>
                <th style={th}>Wallet</th>
                <th style={th}>To</th>
                <th style={th}>Amount</th>
                <th style={th}>Approvals</th>
                <th style={th}>Status</th>
                <th style={th}>Created</th>
              </tr>
            </thead>
            <tbody>
              {items.map((op) => {
                const to = (op.payload?.toAddress as string) ?? ''
                const amount = (op.payload?.amount as string) ?? ''
                const chain = (op.payload?.chain as string) ?? ''
                const isSelected = selected?.operationId === op.operationId
                return (
                  <tr
                    key={op.operationId}
                    onClick={() => setSelected(op)}
                    style={{
                      ...tRow,
                      cursor: 'pointer',
                      background: isSelected ? '#171717' : 'transparent',
                    }}
                  >
                    <td style={{ ...td, ...mono, fontSize: 11 }}>{shorten(op.operationId, 8, 4)}</td>
                    <td style={td}>{op.kind}</td>
                    <td style={{ ...td, ...mono, fontSize: 11 }}>{shorten(op.walletId, 8, 4)}</td>
                    <td style={{ ...td, ...mono, fontSize: 11 }}>{to ? shorten(to, 8, 4) : '--'}</td>
                    <td style={{ ...td, ...mono }}>
                      {amount ? `${amount} ${chain}` : '--'}
                    </td>
                    <td style={td}>{op.approvers?.length ?? 0}</td>
                    <td style={td}><StatusBadge status={op.status} /></td>
                    <td style={{ ...td, color: '#737373' }}>
                      {new Date(op.createdAt).toLocaleString()}
                    </td>
                  </tr>
                )
              })}
              {items.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ ...td, color: '#525252' }}>
                    No operations match this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          {/* Pagination */}
          {total > 25 && (
            <div style={{ marginTop: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                style={{ ...btnGhost, ...disabledStyle(page === 1) }}
              >
                Prev
              </button>
              <span style={{ fontSize: 12, color: '#737373' }}>
                Page {page} of {Math.ceil(total / 25)}
              </span>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page * 25 >= total}
                style={{ ...btnGhost, ...disabledStyle(page * 25 >= total) }}
              >
                Next
              </button>
            </div>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <OperationDetail
            op={selected}
            onClose={() => setSelected(null)}
            onChange={() => {/* tanstack-query refetches via interval */}}
          />
        )}
      </div>
    </div>
  )
}

function OperationDetail({
  op, onClose, onChange,
}: {
  op: Operation
  onClose: () => void
  onChange: () => void
}) {
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [reason, setReason] = useState('')
  const [notes, setNotes] = useState('')
  const [showReject, setShowReject] = useState(false)

  async function approve() {
    setBusy(true); setErr('')
    try {
      await api.approveOperation(op.operationId, notes)
      qc.invalidateQueries({ queryKey: ['mpc', 'operations'] })
      onChange()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Approval failed')
    } finally {
      setBusy(false)
    }
  }

  async function reject() {
    if (!reason.trim()) return
    setBusy(true); setErr('')
    try {
      await api.rejectOperation(op.operationId, reason)
      qc.invalidateQueries({ queryKey: ['mpc', 'operations'] })
      onChange()
      onClose()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Rejection failed')
    } finally {
      setBusy(false)
    }
  }

  const canDecide = op.status === 'pending_approval' || op.status === 'approved'

  return (
    <div style={{ ...card, alignSelf: 'start', position: 'sticky', top: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontWeight: 600, color: '#fff' }}>Operation</div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#737373', cursor: 'pointer', fontSize: 18 }}>×</button>
      </div>

      <div style={{ ...mono, fontSize: 11, color: '#737373', marginTop: 4 }}>{op.operationId}</div>

      <Field title="Kind" value={op.kind} />
      <Field title="Status" value={<StatusBadge status={op.status} />} />
      <Field title="Wallet" value={<span style={mono}>{op.walletId}</span>} />

      {op.payload && Object.keys(op.payload).length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={label}>Payload</div>
          <div style={{ marginTop: 4, padding: 8, background: '#000', border: '1px solid #171717', borderRadius: 4 }}>
            {Object.entries(op.payload).map(([k, v]) => (
              <div key={k} style={{ fontSize: 11, ...mono, color: '#a3a3a3', wordBreak: 'break-all' }}>
                <span style={{ color: '#737373' }}>{k}:</span>{' '}
                {typeof v === 'string' ? v : JSON.stringify(v)}
              </div>
            ))}
          </div>
        </div>
      )}

      {op.approvals && op.approvals.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={label}>Approvals</div>
          {op.approvals.map((a) => (
            <div key={a.approverId} style={{ marginTop: 4, fontSize: 12 }}>
              <span style={mono}>{shorten(a.approverId, 8, 4)}</span>{' '}
              <span style={{ color: '#737373' }}>{new Date(a.approvedAt).toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}

      {op.result && Object.keys(op.result).length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={label}>Result</div>
          {Object.entries(op.result).map(([k, v]) => (
            <div key={k} style={{ fontSize: 11, ...mono, color: '#a3a3a3', wordBreak: 'break-all', marginTop: 4 }}>
              <span style={{ color: '#737373' }}>{k}:</span> {v}
            </div>
          ))}
        </div>
      )}

      {op.rejectionReason && (
        <div style={{ marginTop: 16 }}>
          <div style={label}>Rejection reason</div>
          <div style={{ fontSize: 13, color: '#ef4444', marginTop: 4 }}>{op.rejectionReason}</div>
        </div>
      )}

      {err && <div style={{ ...errorText, marginTop: 12 }}>{err}</div>}

      {canDecide && (
        <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {!showReject && (
            <>
              <input
                placeholder="Optional notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                style={{
                  background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
                  padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
                }}
              />
              <button
                onClick={approve}
                disabled={busy}
                style={{ ...btn, ...disabledStyle(busy) }}
              >
                {busy ? 'Approving...' : 'Approve'}
              </button>
              <button
                onClick={() => setShowReject(true)}
                disabled={busy}
                style={{ ...btnGhost, ...disabledStyle(busy) }}
              >
                Reject
              </button>
            </>
          )}
          {showReject && (
            <>
              <input
                autoFocus
                placeholder="Reason (required)"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                style={{
                  background: '#0a0a0a', border: '1px solid #262626', borderRadius: 6,
                  padding: '6px 12px', color: '#e5e5e5', fontSize: 13,
                }}
              />
              <button
                onClick={reject}
                disabled={busy || !reason.trim()}
                style={{ ...btnDanger, ...disabledStyle(busy || !reason.trim()) }}
              >
                {busy ? 'Rejecting...' : 'Confirm reject'}
              </button>
              <button
                onClick={() => { setShowReject(false); setReason('') }}
                disabled={busy}
                style={{ ...btnGhost, ...disabledStyle(busy) }}
              >
                Cancel
              </button>
            </>
          )}
        </div>
      )}
    </div>
  )
}

function Field({ title, value }: { title: string; value: React.ReactNode }) {
  return (
    <div style={{ marginTop: 12 }}>
      <div style={label}>{title}</div>
      <div style={{ fontSize: 13, marginTop: 2 }}>{value}</div>
    </div>
  )
}
