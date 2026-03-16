import { usePaymentRequests } from '../hooks/use-mpc'
import { StatusBadge } from '../components/StatusBadge'

export function Payments() {
  const { data: payments, error } = usePaymentRequests()

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Payments</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          Deposit/withdrawal lifecycle with MPC co-sign status.
        </p>
      </div>

      {error && <div style={{ color: '#ef4444', fontSize: 13 }}>{(error as Error).message}</div>}

      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #262626', color: '#737373', textAlign: 'left' }}>
            <th style={{ padding: '8px 12px' }}>Merchant</th>
            <th style={{ padding: '8px 12px' }}>Amount</th>
            <th style={{ padding: '8px 12px' }}>Chain</th>
            <th style={{ padding: '8px 12px' }}>Recipient</th>
            <th style={{ padding: '8px 12px' }}>Status</th>
            <th style={{ padding: '8px 12px' }}>Created</th>
          </tr>
        </thead>
        <tbody>
          {payments?.map((pr) => (
            <tr key={pr.id} style={{ borderBottom: '1px solid #171717' }}>
              <td style={{ padding: '8px 12px', fontWeight: 500 }}>{pr.merchant_name || '--'}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>
                {pr.amount} {pr.token || ''}
              </td>
              <td style={{ padding: '8px 12px', textTransform: 'capitalize' }}>{pr.chain}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11 }}>
                {pr.recipient_address.slice(0, 10)}...{pr.recipient_address.slice(-6)}
              </td>
              <td style={{ padding: '8px 12px' }}><StatusBadge status={pr.status} /></td>
              <td style={{ padding: '8px 12px', color: '#737373' }}>
                {new Date(pr.created_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
          {(!payments || payments.length === 0) && (
            <tr>
              <td colSpan={6} style={{ padding: '16px 12px', color: '#525252' }}>
                No payment requests
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
