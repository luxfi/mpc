import { useBridgeConfig, useBridgeNetworks } from '../hooks/use-mpc'

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

export function Bridge() {
  const { data: config } = useBridgeConfig()
  const { data: networks } = useBridgeNetworks()

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Bridge</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          Cross-chain bridge status and transfers.
        </p>
      </div>

      {/* Config cards */}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div style={card}>
          <div style={label}>Signing Wallet</div>
          <div style={{ marginTop: 4, fontFamily: 'monospace', fontSize: 13 }}>
            {config?.signingWalletId ? config.signingWalletId.slice(0, 12) + '...' : 'Not configured'}
          </div>
        </div>
        <div style={card}>
          <div style={label}>Fee Rate</div>
          <div style={{ marginTop: 4, fontSize: 18, fontWeight: 600, color: '#fff' }}>
            {config ? (config.feeRateBps / 100).toFixed(2) : '--'}%
          </div>
        </div>
        <div style={card}>
          <div style={label}>Deposits</div>
          <div style={{ marginTop: 4, color: config?.depositsEnabled ? '#22c55e' : '#ef4444' }}>
            {config?.depositsEnabled ? 'Enabled' : 'Disabled'}
          </div>
        </div>
        <div style={card}>
          <div style={label}>Withdrawals</div>
          <div style={{ marginTop: 4, color: config?.withdrawalsEnabled ? '#22c55e' : '#ef4444' }}>
            {config?.withdrawalsEnabled ? 'Enabled' : 'Disabled'}
          </div>
        </div>
      </div>

      {/* Networks */}
      <div>
        <div style={label}>Supported Networks</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 8 }}>
          {networks?.map((net) => (
            <div
              key={net.chain}
              style={{
                ...card,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 14, fontWeight: 500 }}>{net.name}</span>
                <span style={{
                  background: '#262626',
                  borderRadius: 4,
                  padding: '2px 8px',
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: '#737373',
                }}>
                  {net.type}
                </span>
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: 12 }}>
                <span style={{ color: net.deposit ? '#22c55e' : '#525252' }}>
                  Deposit: {net.deposit ? 'ON' : 'OFF'}
                </span>
                <span style={{ color: net.withdrawal ? '#22c55e' : '#525252' }}>
                  Withdrawal: {net.withdrawal ? 'ON' : 'OFF'}
                </span>
              </div>
            </div>
          ))}
          {(!networks || networks.length === 0) && (
            <div style={{ color: '#525252', fontSize: 13 }}>No networks configured</div>
          )}
        </div>
      </div>
    </div>
  )
}
