import { useAudit } from '../hooks/use-mpc'

export function Audit() {
  const { data: entries, error } = useAudit()

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Audit Log</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          Chronological signing event log.
        </p>
      </div>

      {error && <div style={{ color: '#ef4444', fontSize: 13 }}>{(error as Error).message}</div>}

      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #262626', color: '#737373', textAlign: 'left' }}>
            <th style={{ padding: '8px 12px' }}>Action</th>
            <th style={{ padding: '8px 12px' }}>Resource</th>
            <th style={{ padding: '8px 12px' }}>User</th>
            <th style={{ padding: '8px 12px' }}>IP</th>
            <th style={{ padding: '8px 12px' }}>Date</th>
          </tr>
        </thead>
        <tbody>
          {entries?.map((entry) => (
            <tr key={entry.id} style={{ borderBottom: '1px solid #171717' }}>
              <td style={{ padding: '8px 12px', fontWeight: 500 }}>{entry.action}</td>
              <td style={{ padding: '8px 12px', color: '#a3a3a3' }}>
                {entry.resource_type ? (
                  <>
                    {entry.resource_type}
                    {entry.resource_id && (
                      <span style={{ fontFamily: 'monospace', fontSize: 11, marginLeft: 4 }}>
                        {entry.resource_id.slice(0, 12)}...
                      </span>
                    )}
                  </>
                ) : '--'}
              </td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11, color: '#737373' }}>
                {entry.user_id || '--'}
              </td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: 11, color: '#737373' }}>
                {entry.ip_address || '--'}
              </td>
              <td style={{ padding: '8px 12px', color: '#737373' }}>
                {new Date(entry.created_at).toLocaleString()}
              </td>
            </tr>
          ))}
          {(!entries || entries.length === 0) && (
            <tr>
              <td colSpan={5} style={{ padding: '16px 12px', color: '#525252' }}>
                No audit entries
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
