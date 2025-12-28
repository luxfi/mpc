import { useState } from 'react'
import { useVaults, useWallets } from '../hooks/use-mpc'
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

export function Wallets() {
  const { data: vaults } = useVaults()
  const [selectedVault, setSelectedVault] = useState('')

  // Select first vault by default
  const vaultId = selectedVault || vaults?.[0]?.id || ''
  const { data: wallets } = useWallets(vaultId)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Wallets</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          MPC wallets grouped by vault. Each wallet holds threshold key shares.
        </p>
      </div>

      {/* Vault selector */}
      {vaults && vaults.length > 0 && (
        <div>
          <div style={label}>Vault</div>
          <select
            value={vaultId}
            onChange={(e) => setSelectedVault(e.target.value)}
            style={{
              marginTop: 4,
              background: '#0a0a0a',
              border: '1px solid #262626',
              borderRadius: 6,
              padding: '6px 12px',
              color: '#e5e5e5',
              fontSize: 13,
            }}
          >
            {vaults.map((v) => (
              <option key={v.id} value={v.id}>{v.name}</option>
            ))}
          </select>
        </div>
      )}

      {/* Wallet table */}
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #262626', color: '#737373', textAlign: 'left' }}>
            <th style={{ padding: '8px 12px' }}>Name</th>
            <th style={{ padding: '8px 12px' }}>Key Type</th>
            <th style={{ padding: '8px 12px' }}>Protocol</th>
            <th style={{ padding: '8px 12px' }}>Threshold</th>
            <th style={{ padding: '8px 12px' }}>ETH Address</th>
            <th style={{ padding: '8px 12px' }}>Status</th>
            <th style={{ padding: '8px 12px' }}>Created</th>
          </tr>
        </thead>
        <tbody>
          {wallets?.map((w) => (
            <tr key={w.id} style={{ borderBottom: '1px solid #171717' }}>
              <td style={{ padding: '8px 12px', fontWeight: 500 }}>{w.name || w.wallet_id.slice(0, 12)}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>{w.key_type}</td>
              <td style={{ padding: '8px 12px' }}>{w.protocol ?? '--'}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>
                {w.threshold}/{w.participants.length}
              </td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11 }}>
                {w.eth_address ? `${w.eth_address.slice(0, 10)}...${w.eth_address.slice(-6)}` : '--'}
              </td>
              <td style={{ padding: '8px 12px' }}><StatusBadge status={w.status} /></td>
              <td style={{ padding: '8px 12px', color: '#737373' }}>
                {new Date(w.created_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
          {(!wallets || wallets.length === 0) && (
            <tr>
              <td colSpan={7} style={{ padding: '16px 12px', color: '#525252' }}>
                {vaultId ? 'No wallets in this vault' : 'No vaults available'}
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {/* Wallet detail cards for addresses */}
      {wallets && wallets.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
          {wallets.map((w) => (
            <div key={w.id} style={card}>
              <div style={{ fontWeight: 500, fontSize: 14, color: '#fff', marginBottom: 8 }}>
                {w.name || w.wallet_id.slice(0, 12)}
              </div>
              {w.eth_address && (
                <div style={{ fontSize: 11, color: '#a3a3a3', marginBottom: 4 }}>
                  <span style={label}>ETH</span>{' '}
                  <span style={{ fontFamily: 'monospace' }}>{w.eth_address}</span>
                </div>
              )}
              {w.btc_address && (
                <div style={{ fontSize: 11, color: '#a3a3a3', marginBottom: 4 }}>
                  <span style={label}>BTC</span>{' '}
                  <span style={{ fontFamily: 'monospace' }}>{w.btc_address}</span>
                </div>
              )}
              {w.sol_address && (
                <div style={{ fontSize: 11, color: '#a3a3a3' }}>
                  <span style={label}>SOL</span>{' '}
                  <span style={{ fontFamily: 'monospace' }}>{w.sol_address}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
