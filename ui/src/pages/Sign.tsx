import { useState, type FormEvent } from 'react'
import { useLocation } from 'wouter'
import { useVaults, useWallets } from '../hooks/use-mpc'
import { card, label, btn, h1, sub, errorText, disabledStyle } from '../lib/styles'

// Sign / build a transaction.
//
// The unified Operation view is read-only — Operation creation goes through
// /v1/transactions which the backend keeps as the internal entry point. This
// page collects the inputs, calls the legacy POST, and the user is routed to
// /operations to approve and watch it sign.

const chains = ['ethereum', 'bitcoin', 'lux', 'solana', 'polygon', 'arbitrum', 'base', 'optimism']

export function Sign() {
  const [, navigate] = useLocation()
  const { data: vaults } = useVaults()
  const [vaultId, setVaultId] = useState('')
  const effectiveVault = vaultId || vaults?.[0]?.id || ''
  const { data: wallets } = useWallets(effectiveVault)

  const [walletId, setWalletId] = useState('')
  const [chain, setChain] = useState('ethereum')
  const [to, setTo] = useState('')
  const [amount, setAmount] = useState('')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!walletId || !to || !amount) return
    setBusy(true); setErr('')
    try {
      const res = await fetch('/v1/transactions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('mpc_token') ?? ''}`,
        },
        body: JSON.stringify({
          wallet_id: walletId,
          tx_type: 'send',
          chain,
          to_address: to,
          amount,
          token: token || undefined,
        }),
      })
      if (!res.ok) {
        const txt = await res.text()
        throw new Error(txt || `HTTP ${res.status}`)
      }
      navigate('/operations')
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Submission failed')
    } finally {
      setBusy(false)
    }
  }

  const selectedWallet = wallets?.find((w) => w.id === walletId)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={h1}>New transaction</h1>
        <p style={sub}>
          Build a transaction and submit for approval. Goes through your org's policy chain
          before signing.
        </p>
      </div>

      {err && <div style={errorText}>{err}</div>}

      <form onSubmit={submit} style={{ ...card, maxWidth: 640, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <Field title="Vault">
          <select
            value={effectiveVault}
            onChange={(e) => { setVaultId(e.target.value); setWalletId('') }}
            style={fieldInput}
          >
            <option value="">Select a vault…</option>
            {(vaults ?? []).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
          </select>
        </Field>

        <Field title="Wallet">
          <select
            value={walletId}
            onChange={(e) => setWalletId(e.target.value)}
            disabled={!effectiveVault}
            style={fieldInput}
          >
            <option value="">Select a wallet…</option>
            {(wallets ?? []).map((w) => (
              <option key={w.id} value={w.id}>
                {w.name ?? w.wallet_id} ({w.key_type})
              </option>
            ))}
          </select>
        </Field>

        {selectedWallet && (
          <div style={{ fontSize: 11, color: '#737373', fontFamily: 'monospace' }}>
            ETH: {selectedWallet.eth_address ?? '--'}
            {selectedWallet.btc_address && <><br />BTC: {selectedWallet.btc_address}</>}
            {selectedWallet.sol_address && <><br />SOL: {selectedWallet.sol_address}</>}
          </div>
        )}

        <Field title="Chain">
          <select value={chain} onChange={(e) => setChain(e.target.value)} style={fieldInput}>
            {chains.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </Field>

        <Field title="Destination address">
          <input
            required
            placeholder="0x..."
            value={to}
            onChange={(e) => setTo(e.target.value)}
            style={{ ...fieldInput, fontFamily: 'monospace' }}
          />
        </Field>

        <Field title="Amount">
          <input
            required
            placeholder="0.0"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            style={{ ...fieldInput, fontFamily: 'monospace' }}
          />
        </Field>

        <Field title="Token contract (optional)">
          <input
            placeholder="0x... — leave blank for native"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            style={{ ...fieldInput, fontFamily: 'monospace' }}
          />
        </Field>

        <button
          type="submit"
          disabled={busy || !walletId || !to || !amount}
          style={{ ...btn, ...disabledStyle(busy || !walletId || !to || !amount), marginTop: 8 }}
        >
          {busy ? 'Submitting...' : 'Submit for approval'}
        </button>
      </form>
    </div>
  )
}

function Field({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={label}>{title}</div>
      <div style={{ marginTop: 4 }}>{children}</div>
    </div>
  )
}

const fieldInput: React.CSSProperties = {
  width: '100%',
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 6,
  padding: '6px 12px',
  color: '#e5e5e5',
  fontSize: 13,
}
