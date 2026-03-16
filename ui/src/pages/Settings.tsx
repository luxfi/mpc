import { useInfo, useStatus } from '../hooks/use-mpc'
import { StatusBadge } from '../components/StatusBadge'

const card: React.CSSProperties = {
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 8,
  padding: 16,
}

const label: React.CSSProperties = {
  fontSize: 12,
  color: '#737373',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
}

export function Settings() {
  const { data: info } = useInfo()
  const { data: cluster } = useStatus()

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Settings</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          Node configuration, HSM status, and threshold config.
        </p>
      </div>

      {/* Service info */}
      <div style={card}>
        <div style={{ ...label, marginBottom: 12 }}>Service Info</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
          <div>
            <div style={label}>Service</div>
            <div style={{ fontSize: 14, marginTop: 2 }}>{info?.name ?? '--'}</div>
          </div>
          <div>
            <div style={label}>Version</div>
            <div style={{ fontSize: 14, fontFamily: 'monospace', marginTop: 2 }}>{info?.version ?? '--'}</div>
          </div>
          <div>
            <div style={label}>Key Types</div>
            <div style={{ fontSize: 14, fontFamily: 'monospace', marginTop: 2 }}>
              {info?.key_types?.join(', ') ?? '--'}
            </div>
          </div>
          <div>
            <div style={label}>Protocols</div>
            <div style={{ fontSize: 14, marginTop: 2 }}>
              {info?.protocols?.join(', ') ?? '--'}
            </div>
          </div>
        </div>
      </div>

      {/* Supported chains */}
      <div style={card}>
        <div style={{ ...label, marginBottom: 12 }}>Supported Chains</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {info?.supported_chains?.map((chain) => (
            <span
              key={chain}
              style={{
                background: '#262626',
                borderRadius: 4,
                padding: '4px 10px',
                fontSize: 12,
                color: '#d4d4d4',
              }}
            >
              {chain}
            </span>
          ))}
          {(!info?.supported_chains || info.supported_chains.length === 0) && (
            <span style={{ color: '#525252', fontSize: 13 }}>--</span>
          )}
        </div>
      </div>

      {/* Cluster config */}
      <div style={card}>
        <div style={{ ...label, marginBottom: 12 }}>Cluster Configuration</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
          <div>
            <div style={label}>Node ID</div>
            <div style={{ fontSize: 14, fontFamily: 'monospace', marginTop: 2 }}>{cluster?.node_id ?? '--'}</div>
          </div>
          <div>
            <div style={label}>Mode</div>
            <div style={{ fontSize: 14, marginTop: 2 }}>{cluster?.mode ?? '--'}</div>
          </div>
          <div>
            <div style={label}>Threshold</div>
            <div style={{ fontSize: 14, fontFamily: 'monospace', marginTop: 2 }}>
              {cluster ? `${cluster.threshold}-of-${cluster.expected_peers}` : '--'}
            </div>
          </div>
          <div>
            <div style={label}>Peers</div>
            <div style={{ fontSize: 14, fontFamily: 'monospace', marginTop: 2 }}>
              {cluster ? `${cluster.connected_peers}/${cluster.expected_peers}` : '--'}
            </div>
          </div>
          <div>
            <div style={label}>Status</div>
            <div style={{ marginTop: 2 }}>
              {cluster ? <StatusBadge status={cluster.ready ? 'running' : 'degraded'} /> : '--'}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
