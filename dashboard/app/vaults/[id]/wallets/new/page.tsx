'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'

type KeyType = 'secp256k1' | 'ed25519'
type Step = 'type' | 'name' | 'generate' | 'result'

interface KeygenResult {
  wallet_id: string
  eth_address: string
  btc_address: string
  sol_address: string
  public_key: string
}

export default function NewWalletPage() {
  const params = useParams<{ id: string }>()
  const router = useRouter()

  const [step, setStep] = useState<Step>('type')
  const [keyType, setKeyType] = useState<KeyType>('secp256k1')
  const [walletName, setWalletName] = useState('')
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<KeygenResult | null>(null)

  async function handleGenerate() {
    if (!walletName.trim()) return
    setGenerating(true)
    setError('')
    setStep('generate')

    try {
      const res = await fetch(`/api/vaults/${params.id}/wallets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('access_token')}`,
        },
        body: JSON.stringify({ name: walletName, key_type: keyType }),
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.error || 'Key generation failed')
      }

      setResult(data)
      setStep('result')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Key generation failed')
      setStep('name')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/vaults" className="hover:text-foreground">Vaults</Link>
          <span>/</span>
          <Link href={`/vaults/${params.id}`} className="hover:text-foreground">Vault</Link>
          <span>/</span>
          <span>New Wallet</span>
        </div>

        <h1 className="mb-8 text-2xl font-semibold tracking-tight">Generate New Wallet</h1>

        <div className="mx-auto max-w-lg">
          {/* Step indicator */}
          <div className="mb-8 flex items-center justify-between">
            {(['type', 'name', 'generate', 'result'] as Step[]).map((s, i) => (
              <div key={s} className="flex items-center gap-2">
                <div
                  className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold ${
                    step === s
                      ? 'bg-primary text-primary-foreground'
                      : i < ['type', 'name', 'generate', 'result'].indexOf(step)
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : 'bg-muted text-muted-foreground'
                  }`}
                >
                  {i + 1}
                </div>
                {i < 3 && <div className="h-px w-12 bg-border sm:w-16" />}
              </div>
            ))}
          </div>

          {/* Step: Choose key type */}
          {step === 'type' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Choose Key Type</h2>
              <div className="grid gap-3 sm:grid-cols-2">
                {(['secp256k1', 'ed25519'] as KeyType[]).map((t) => (
                  <button
                    key={t}
                    onClick={() => setKeyType(t)}
                    className={`rounded-lg border p-4 text-left transition-colors ${
                      keyType === t
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-foreground/20'
                    }`}
                  >
                    <p className="font-semibold font-mono text-sm">{t}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {t === 'secp256k1'
                        ? 'Bitcoin, Ethereum, Lux, XRPL'
                        : 'Solana, TON, Polkadot'}
                    </p>
                  </button>
                ))}
              </div>
              <div className="flex justify-end">
                <button
                  onClick={() => setStep('name')}
                  className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                >
                  Next
                </button>
              </div>
            </div>
          )}

          {/* Step: Name wallet */}
          {step === 'name' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Name Your Wallet</h2>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                  Wallet Name
                </label>
                <input
                  type="text"
                  value={walletName}
                  onChange={(e) => setWalletName(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="Hot Wallet"
                />
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
              <div className="flex justify-between">
                <button
                  onClick={() => setStep('type')}
                  className="rounded-md border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent"
                >
                  Back
                </button>
                <button
                  onClick={handleGenerate}
                  disabled={!walletName.trim()}
                  className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
                >
                  Generate
                </button>
              </div>
            </div>
          )}

          {/* Step: Generating */}
          {step === 'generate' && (
            <div className="flex flex-col items-center py-12">
              <div className="mb-4 h-8 w-8 animate-spin rounded-full border-2 border-muted border-t-primary" />
              <p className="text-sm text-muted-foreground">
                Running distributed key generation...
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                This may take up to 30 seconds.
              </p>
            </div>
          )}

          {/* Step: Result */}
          {step === 'result' && result && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <h2 className="text-lg font-semibold">Wallet Created</h2>
              </div>

              <div className="space-y-3 rounded-lg border border-border bg-muted/50 p-4">
                {result.eth_address && (
                  <div>
                    <p className="text-xs text-muted-foreground">ETH Address</p>
                    <p className="font-mono text-sm break-all">{result.eth_address}</p>
                  </div>
                )}
                {result.btc_address && (
                  <div>
                    <p className="text-xs text-muted-foreground">BTC Address</p>
                    <p className="font-mono text-sm break-all">{result.btc_address}</p>
                  </div>
                )}
                {result.sol_address && (
                  <div>
                    <p className="text-xs text-muted-foreground">SOL Address</p>
                    <p className="font-mono text-sm break-all">{result.sol_address}</p>
                  </div>
                )}
                <div>
                  <p className="text-xs text-muted-foreground">Public Key</p>
                  <p className="font-mono text-xs break-all">{result.public_key}</p>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={() => router.push(`/vaults/${params.id}`)}
                  className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                >
                  Done
                </button>
              </div>
            </div>
          )}
        </div>
      </main>
    </>
  )
}
