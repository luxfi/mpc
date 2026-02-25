'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'
import { api } from '@/lib/api'

export default function BridgeFeesPage() {
  const [feeRateBps, setFeeRateBps] = useState(100)
  const [minFeeBps, setMinFeeBps] = useState(0)
  const [maxFeeBps, setMaxFeeBps] = useState(0)
  const [feeCollector, setFeeCollector] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    api.getBridgeConfig().then((c) => {
      setFeeRateBps(c.feeRateBps ?? 100)
      setMinFeeBps(c.minFeeBps ?? 0)
      setMaxFeeBps(c.maxFeeBps ?? 0)
      setFeeCollector(c.feeCollector ?? '')
    }).catch(() => {})
  }, [])

  async function handleSave() {
    setSaving(true)
    setError('')
    setSuccess('')
    try {
      await api.updateBridgeConfig({
        fee_rate_bps: feeRateBps,
        min_fee_bps: minFeeBps,
        max_fee_bps: maxFeeBps,
        fee_collector: feeCollector,
      })
      setSuccess('Fee configuration saved')
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/bridge" className="hover:text-foreground">Bridge</Link>
          <span>/</span>
          <span>Fee Configuration</span>
        </div>

        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Fee Configuration</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Set bridge fee rates and collector addresses.
          </p>
        </div>

        {error && <p className="mb-4 text-sm text-destructive">{error}</p>}
        {success && <p className="mb-4 text-sm text-green-500">{success}</p>}

        <div className="rounded-lg border border-border bg-card p-6">
          <div className="space-y-6">
            <div className="grid gap-6 sm:grid-cols-3">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                  Fee Rate (basis points)
                </label>
                <input
                  type="number"
                  value={feeRateBps}
                  onChange={(e) => setFeeRateBps(parseInt(e.target.value) || 0)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
                <p className="mt-1 text-xs text-muted-foreground">
                  100 = 1%, 50 = 0.5%, 10 = 0.1%
                </p>
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                  Min Fee (basis points)
                </label>
                <input
                  type="number"
                  value={minFeeBps}
                  onChange={(e) => setMinFeeBps(parseInt(e.target.value) || 0)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                  Max Fee (basis points)
                </label>
                <input
                  type="number"
                  value={maxFeeBps}
                  onChange={(e) => setMaxFeeBps(parseInt(e.target.value) || 0)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                Fee Collector Address
              </label>
              <input
                type="text"
                value={feeCollector}
                onChange={(e) => setFeeCollector(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="0x..."
              />
              <p className="mt-1 text-xs text-muted-foreground">
                Address that receives collected bridge fees.
              </p>
            </div>

            <div className="rounded-md bg-muted/50 p-4">
              <p className="text-sm">
                Current effective fee: <span className="font-semibold">{(feeRateBps / 100).toFixed(2)}%</span>
                {minFeeBps > 0 && <span className="text-muted-foreground"> (min {(minFeeBps / 100).toFixed(2)}%)</span>}
                {maxFeeBps > 0 && <span className="text-muted-foreground"> (max {(maxFeeBps / 100).toFixed(2)}%)</span>}
              </p>
            </div>

            <button
              onClick={handleSave}
              disabled={saving}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save Fee Configuration'}
            </button>
          </div>
        </div>
      </main>
    </>
  )
}
