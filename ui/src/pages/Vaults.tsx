import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useVaults } from '../hooks/use-mpc'
import { api } from '../lib/api'

const card: React.CSSProperties = {
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 8,
  padding: 16,
}

const input: React.CSSProperties = {
  width: '100%',
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 6,
  padding: '6px 12px',
  color: '#e5e5e5',
  fontSize: 13,
}

const btn: React.CSSProperties = {
  padding: '6px 16px',
  borderRadius: 6,
  fontSize: 13,
  fontWeight: 500,
  cursor: 'pointer',
  border: 'none',
}

export function Vaults() {
  const queryClient = useQueryClient()
  const { data: vaults } = useVaults()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [creating, setCreating] = useState(false)
  const [err, setErr] = useState('')

  async function handleCreate() {
    if (!name.trim()) return
    setCreating(true)
    setErr('')
    try {
      await api.createVault({ name, description })
      setName('')
      setDescription('')
      queryClient.invalidateQueries({ queryKey: ['mpc', 'vaults'] })
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to create vault')
    } finally {
      setCreating(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: '#fff' }}>Vaults</h1>
        <p style={{ fontSize: 13, color: '#737373', marginTop: 4 }}>
          Cold storage vaults with Shamir backup status.
        </p>
      </div>

      {err && <div style={{ color: '#ef4444', fontSize: 13 }}>{err}</div>}

      {/* Create form */}
      <div style={card}>
        <div style={{ fontSize: 12, color: '#737373', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 12 }}>
          Create Vault
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            style={{ ...input, maxWidth: 240 }}
            placeholder="Vault name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            style={{ ...input, maxWidth: 320 }}
            placeholder="Description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <button
            style={{ ...btn, background: '#fff', color: '#000', opacity: creating || !name.trim() ? 0.5 : 1 }}
            disabled={creating || !name.trim()}
            onClick={handleCreate}
          >
            {creating ? 'Creating...' : 'Create'}
          </button>
        </div>
      </div>

      {/* Vault grid */}
      {!vaults || vaults.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', color: '#525252' }}>
          No vaults yet.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
          {vaults.map((v) => (
            <div key={v.id} style={card}>
              <div style={{ fontWeight: 500, color: '#fff' }}>{v.name}</div>
              {v.description && (
                <div style={{ fontSize: 12, color: '#737373', marginTop: 4 }}>{v.description}</div>
              )}
              <div style={{ fontSize: 11, color: '#525252', marginTop: 8, fontFamily: 'monospace' }}>
                {v.id.slice(0, 16)}...
              </div>
              <div style={{ fontSize: 11, color: '#525252', marginTop: 2 }}>
                Created {new Date(v.created_at).toLocaleDateString()}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
