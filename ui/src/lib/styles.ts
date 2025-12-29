// Shared inline-style tokens. Single source of truth for the dashboard.
import type { CSSProperties } from 'react'

export const card: CSSProperties = {
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 8,
  padding: 16,
}

export const label: CSSProperties = {
  fontSize: 12,
  color: '#737373',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
}

export const input: CSSProperties = {
  width: '100%',
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 6,
  padding: '6px 12px',
  color: '#e5e5e5',
  fontSize: 13,
}

export const btn: CSSProperties = {
  padding: '6px 16px',
  borderRadius: 6,
  fontSize: 13,
  fontWeight: 500,
  cursor: 'pointer',
  border: 'none',
  background: '#fff',
  color: '#000',
}

export const btnGhost: CSSProperties = {
  ...btn,
  background: 'transparent',
  color: '#a3a3a3',
  border: '1px solid #262626',
}

export const btnDanger: CSSProperties = {
  ...btn,
  background: '#ef4444',
  color: '#fff',
}

export const table: CSSProperties = {
  width: '100%',
  borderCollapse: 'collapse',
  fontSize: 13,
}

export const th: CSSProperties = { padding: '8px 12px', textAlign: 'left' }
export const td: CSSProperties = { padding: '8px 12px' }

export const tHead: CSSProperties = {
  borderBottom: '1px solid #262626',
  color: '#737373',
}

export const tRow: CSSProperties = { borderBottom: '1px solid #171717' }

export const mono: CSSProperties = { fontFamily: 'monospace' }

export const h1: CSSProperties = { fontSize: 20, fontWeight: 600, color: '#fff' }
export const sub: CSSProperties = { fontSize: 13, color: '#737373', marginTop: 4 }

export const errorText: CSSProperties = { color: '#ef4444', fontSize: 13 }

export function disabledStyle(disabled: boolean): CSSProperties {
  return disabled ? { opacity: 0.5, cursor: 'not-allowed' } : {}
}

export function shorten(s: string, head = 8, tail = 6): string {
  if (!s) return '--'
  if (s.length <= head + tail + 3) return s
  return `${s.slice(0, head)}...${s.slice(-tail)}`
}
