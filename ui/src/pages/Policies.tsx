import { useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { usePolicies } from '../hooks/use-mpc'
import { api } from '../lib/api'
import { StatusBadge } from '../components/StatusBadge'

const card: React.CSSProperties = {
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 8,
  padding: 16,
}

const input: React.CSSProperties = {
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 6,
  padding: '6px 12px',
  color: '#e5e5e5',
  fontSize: 13,
  width: '100%',
}

const actionOptions = ['approve', 'deny', 'require_approval']

export function Policies() {
  const queryClient = useQueryClient()
  const { data: policies } = usePolicies()
  const [name, setName] = useState('')
  const [action, setAction] = useState('require_approval')
  const [priority, setPriority] = useState(0)
  const [requiredApprovers, setRequiredApprovers] = useState(1)
  const [approverRoles, setApproverRoles] = useState('admin,owner')
  const [creating, setCreating] = useState(false)
  const [err, setErr] = useState('')

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    setErr('')
    try {
      await api.createPolicy({
        name,
        action,
        priority,
        conditions: {},
        required_approvers: requiredApprovers,
        approver_roles: approverRoles.split(',').map((r) => r.trim()).filter(Boolean),
      })
      setName('')
      setPriority(0)
      setRequiredApprovers(1)
      queryClient.invalidateQueries({ queryKey: ['mpc', 'policies'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to create policy')
    } finally {
      setCreating(false)
    }
  }

  async function handleToggle(id: string, enabled: boolean) {
    try {
      await api.updatePolicy(id, { enabled: !enabled })
      queryClient.invalidateQueries({ queryKey: ['mpc', 'policies'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to update policy')
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deletePolicy(id)
      queryClient.invalidateQueries({ queryKey: ['mpc', 'policies'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to delete policy')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Policies</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          Signing policies: auto-approve, requires-N, blocked.
        </p>
      </div>

      {err && <div style={{ color: '#ef4444', fontSize: 13 }}>{err}</div>}

      {/* Create form */}
      <form onSubmit={handleCreate} style={card}>
        <div style={{ fontSize: 12, color: '#737373', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 12 }}>
          Create Policy
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8 }}>
          <input style={input} placeholder="Policy name" required value={name} onChange={(e) => setName(e.target.value)} />
          <select style={input} value={action} onChange={(e) => setAction(e.target.value)}>
            {actionOptions.map((a) => <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
          </select>
          <input style={input} type="number" placeholder="Priority" value={priority} onChange={(e) => setPriority(Number(e.target.value))} />
          <input style={input} type="number" min={1} placeholder="Approvers" value={requiredApprovers} onChange={(e) => setRequiredApprovers(Number(e.target.value))} />
        </div>
        <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
          <input style={{ ...input, flex: 1 }} placeholder="Approver roles (comma-separated)" value={approverRoles} onChange={(e) => setApproverRoles(e.target.value)} />
          <button
            type="submit"
            disabled={creating || !name.trim()}
            style={{ padding: '6px 16px', borderRadius: 6, fontSize: 13, fontWeight: 500, cursor: 'pointer', border: 'none', background: '#fff', color: '#000', opacity: creating || !name.trim() ? 0.5 : 1 }}
          >
            {creating ? 'Creating...' : 'Create'}
          </button>
        </div>
      </form>

      {/* Table */}
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #262626', color: '#737373', textAlign: 'left' }}>
            <th style={{ padding: '8px 12px' }}>Name</th>
            <th style={{ padding: '8px 12px' }}>Action</th>
            <th style={{ padding: '8px 12px' }}>Priority</th>
            <th style={{ padding: '8px 12px' }}>Approvers</th>
            <th style={{ padding: '8px 12px' }}>Status</th>
            <th style={{ padding: '8px 12px', textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {policies?.map((p) => (
            <tr key={p.id} style={{ borderBottom: '1px solid #171717' }}>
              <td style={{ padding: '8px 12px', fontWeight: 500 }}>{p.name}</td>
              <td style={{ padding: '8px 12px', textTransform: 'capitalize' }}>{p.action.replace(/_/g, ' ')}</td>
              <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>{p.priority}</td>
              <td style={{ padding: '8px 12px' }}>{p.required_approvers} ({p.approver_roles.join(', ')})</td>
              <td style={{ padding: '8px 12px' }}><StatusBadge status={p.enabled ? 'enabled' : 'disabled'} /></td>
              <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                <button
                  onClick={() => handleToggle(p.id, p.enabled)}
                  style={{ background: 'none', border: 'none', color: '#a3a3a3', cursor: 'pointer', fontSize: 12, marginRight: 12 }}
                >
                  {p.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  onClick={() => handleDelete(p.id)}
                  style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 12 }}
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
          {(!policies || policies.length === 0) && (
            <tr>
              <td colSpan={6} style={{ padding: '16px 12px', color: '#525252' }}>
                No policies configured
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
