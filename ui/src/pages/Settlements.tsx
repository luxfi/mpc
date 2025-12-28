import { useState } from 'react'
import { useSettlements } from '../hooks/use-mpc'
import { StatusBadge } from '../components/StatusBadge'

const statusOptions = ['all', 'pending', 'hsm_signing', 'broadcast', 'confirming', 'finalized', 'verified', 'failed']

export function Settlements() {
  const [statusFilter, setStatusFilter] = useState('all')
  const filters = statusFilter !== 'all' ? { status: statusFilter } : undefined
  const { data: settlements, error } = useSettlements(filters)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Settlements</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          Intent &rarr; sign &rarr; broadcast &rarr; confirm lifecycle.
        </p>
      </div>

      {error && <div style={{ color: '#ef4444', fontSize: 13 }}>{(error as Error).message}</div>}

      {/* Filter */}
      <div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{
            background: '#0a0a0a',
            border: '1px solid #262626',
            borderRadius: 6,
            padding: '6px 12px',
            color: '#e5e5e5',
            fontSize: 13,
          }}
        >
          {statusOptions.map((s) => (
            <option key={s} value={s}>{s === 'all' ? 'All Status' : s.replace(/_/g, ' ')}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #262626', color: '#737373', textAlign: 'left' }}>
            <th style={{ padding: '8px 12px' }}>Settlement ID</th>
            <th style={{ padding: '8px 12px' }}>Intent</th>
            <th style={{ padding: '8px 12px' }}>HSM Sigs</th>
            <th style={{ padding: '8px 12px' }}>Verified</th>
            <th style={{ padding: '8px 12px' }}>Status</th>
            <th style={{ padding: '8px 12px' }}>Date</th>
          </tr>
        </thead>
        <tbody>
          {settlements?.map((s) => (
            <tr key={s.id} style={{ borderBottom: '1px solid #171717' }}>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11 }}>{s.id.slice(0, 12)}...</td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11 }}>{s.intent_id.slice(0, 12)}...</td>
              <td style={{ padding: '8px 12px' }}>{s.hsm_signatures?.length ?? 0}</td>
              <td style={{ padding: '8px 12px' }}>
                <span style={{ color: s.transfer_agency_verified ? '#22c55e' : '#737373' }}>
                  {s.transfer_agency_verified ? 'Yes' : 'No'}
                </span>
              </td>
              <td style={{ padding: '8px 12px' }}><StatusBadge status={s.status} /></td>
              <td style={{ padding: '8px 12px', color: '#737373' }}>
                {new Date(s.created_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
          {(!settlements || settlements.length === 0) && (
            <tr>
              <td colSpan={6} style={{ padding: '16px 12px', color: '#525252' }}>
                No settlements found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
