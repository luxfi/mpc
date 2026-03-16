import { useStatus, useVaults, useTransactions } from '../hooks/use-mpc'
import { StatusBadge } from '../components/StatusBadge'

const card: React.CSSProperties = {
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 8,
  padding: 16,
  minWidth: 140,
}

const label: React.CSSProperties = {
  fontSize: 12,
  color: '#737373',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
}

const value: React.CSSProperties = {
  fontSize: 28,
  fontWeight: 600,
  color: '#fff',
  marginTop: 4,
  fontFamily: 'monospace',
}

export function Dashboard() {
  const { data: cluster } = useStatus()
  const { data: vaults } = useVaults()
  const { data: txList } = useTransactions()

  const pending = txList?.filter((t) => t.status === 'pending' || t.status === 'pending_approval').length ?? 0
  const recent = txList?.slice(0, 8) ?? []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Dashboard</h1>
        {cluster && (
          <StatusBadge status={cluster.ready ? 'running' : 'degraded'} />
        )}
      </div>

      {/* Stat cards */}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div style={card}>
          <div style={label}>Vaults</div>
          <div style={value}>{vaults?.length ?? '--'}</div>
        </div>
        <div style={card}>
          <div style={label}>Pending TX</div>
          <div style={value}>{pending}</div>
        </div>
        <div style={card}>
          <div style={label}>Peers</div>
          <div style={value}>
            {cluster ? `${cluster.connected_peers}/${cluster.expected_peers}` : '--'}
          </div>
        </div>
        <div style={card}>
          <div style={label}>Threshold</div>
          <div style={value}>
            {cluster ? `${cluster.threshold}-of-${cluster.expected_peers}` : '--'}
          </div>
        </div>
        <div style={card}>
          <div style={label}>Version</div>
          <div style={{ ...value, fontSize: 16 }}>
            {cluster?.version ?? '--'}
          </div>
        </div>
      </div>

      {/* Cluster info */}
      {cluster && (
        <div style={card}>
          <div style={label}>Cluster Node</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: cluster.ready ? '#22c55e' : '#f59e0b',
            }} />
            <span style={{ fontFamily: 'monospace', fontSize: 14, color: '#fff' }}>{cluster.node_id}</span>
            <span style={{ fontSize: 12, color: '#737373', marginLeft: 'auto' }}>{cluster.mode}</span>
          </div>
        </div>
      )}

      {/* Recent transactions */}
      <div>
        <div style={label}>Recent Transactions</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 8, fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #262626', color: '#737373', textAlign: 'left' }}>
              <th style={{ padding: '8px 12px' }}>Type</th>
              <th style={{ padding: '8px 12px' }}>Chain</th>
              <th style={{ padding: '8px 12px' }}>Amount</th>
              <th style={{ padding: '8px 12px' }}>Status</th>
              <th style={{ padding: '8px 12px' }}>Date</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((tx) => (
              <tr key={tx.id} style={{ borderBottom: '1px solid #171717' }}>
                <td style={{ padding: '8px 12px', textTransform: 'capitalize' }}>{tx.tx_type}</td>
                <td style={{ padding: '8px 12px' }}>{tx.chain}</td>
                <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>{tx.amount ?? '--'}</td>
                <td style={{ padding: '8px 12px' }}><StatusBadge status={tx.status} /></td>
                <td style={{ padding: '8px 12px', color: '#737373' }}>
                  {new Date(tx.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
            {recent.length === 0 && (
              <tr>
                <td colSpan={5} style={{ padding: '16px 12px', color: '#525252' }}>
                  No recent transactions
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
