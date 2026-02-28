'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { DeployWizard } from '@/components/smart-wallets/deploy-wizard'

type WalletType = 'safe' | 'erc4337'
type DeployStep = 'type' | 'config' | 'advanced' | 'deploy'

interface DeployConfig {
  type: WalletType
  chain: string
  chainId: number
  owners: string[]
  threshold: number
  factoryAddress: string
  salt: string
}

const chains = [
  { name: 'Ethereum', chainId: 1 },
  { name: 'Lux C-Chain', chainId: 96369 },
  { name: 'Lux Testnet', chainId: 96368 },
  { name: 'Zoo', chainId: 200200 },
  { name: 'Hanzo', chainId: 36963 },
]

export default function DeploySmartWalletPage() {
  const params = useParams<{ id: string }>()
  const router = useRouter()

  const [step, setStep] = useState<DeployStep>('type')
  const [config, setConfig] = useState<DeployConfig>({
    type: 'safe',
    chain: 'Ethereum',
    chainId: 1,
    owners: [''],
    threshold: 1,
    factoryAddress: '',
    salt: '',
  })
  const [deploying, setDeploying] = useState(false)
  const [deployedAddress, setDeployedAddress] = useState('')
  const [error, setError] = useState('')

  function addOwner() {
    setConfig((c) => ({ ...c, owners: [...c.owners, ''] }))
  }

  function updateOwner(index: number, value: string) {
    setConfig((c) => {
      const owners = [...c.owners]
      owners[index] = value
      return { ...c, owners }
    })
  }

  function removeOwner(index: number) {
    setConfig((c) => ({
      ...c,
      owners: c.owners.filter((_, i) => i !== index),
    }))
  }

  async function handleDeploy() {
    setDeploying(true)
    setError('')
    try {
      // TODO: call deploy API
      await new Promise((resolve) => setTimeout(resolve, 5000))
      setDeployedAddress('0x9876...fedc')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deployment failed')
    } finally {
      setDeploying(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8 px-4 py-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Deploy Smart Wallet
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Deploy a Safe or ERC-4337 wallet backed by MPC key{' '}
          <span className="font-mono">{params.id}</span>
        </p>
      </div>

      {/* Step indicator */}
      <DeployWizard currentStep={step} />

      {/* Step 1: Choose type */}
      {step === 'type' && (
        <section className="space-y-4">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
            Step 1: Choose Wallet Type
          </h2>
          <div className="grid grid-cols-2 gap-4">
            {(['safe', 'erc4337'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setConfig((c) => ({ ...c, type: t }))}
                className={`rounded-lg border p-6 text-left transition-colors ${
                  config.type === t
                    ? 'border-primary bg-primary/5'
                    : 'border-border hover:border-muted-foreground'
                }`}
              >
                <p className="text-sm font-medium">
                  {t === 'safe' ? 'Safe (Gnosis Safe)' : 'ERC-4337 Account'}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {t === 'safe'
                    ? 'Multi-sig smart wallet with on-chain approvals'
                    : 'Account abstraction with bundler and paymaster support'}
                </p>
              </button>
            ))}
          </div>
          <button
            onClick={() => setStep('config')}
            className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            Next
          </button>
        </section>
      )}

      {/* Step 2: Chain, owners, threshold */}
      {step === 'config' && (
        <section className="space-y-6">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
            Step 2: Configuration
          </h2>

          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="chain">
              Chain
            </label>
            <select
              id="chain"
              value={config.chainId}
              onChange={(e) => {
                const chain = chains.find(
                  (c) => c.chainId === Number(e.target.value)
                )
                if (chain) {
                  setConfig((c) => ({
                    ...c,
                    chain: chain.name,
                    chainId: chain.chainId,
                  }))
                }
              }}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {chains.map((c) => (
                <option key={c.chainId} value={c.chainId}>
                  {c.name} ({c.chainId})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Owners</label>
            {config.owners.map((owner, i) => (
              <div key={i} className="flex gap-2">
                <input
                  type="text"
                  value={owner}
                  onChange={(e) => updateOwner(i, e.target.value)}
                  placeholder="0x..."
                  className="flex-1 rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
                {config.owners.length > 1 && (
                  <button
                    onClick={() => removeOwner(i)}
                    className="rounded-md border border-border px-3 py-2 text-sm text-muted-foreground hover:bg-accent"
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button
              onClick={addOwner}
              className="text-sm font-medium text-primary hover:underline"
            >
              + Add Owner
            </button>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="sw-threshold">
              Threshold
            </label>
            <input
              id="sw-threshold"
              type="number"
              min={1}
              max={config.owners.length}
              value={config.threshold}
              onChange={(e) =>
                setConfig((c) => ({ ...c, threshold: Number(e.target.value) }))
              }
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => setStep('type')}
              className="flex-1 rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent"
            >
              Back
            </button>
            <button
              onClick={() => setStep('advanced')}
              className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Next
            </button>
          </div>
        </section>
      )}

      {/* Step 3: Advanced options */}
      {step === 'advanced' && (
        <section className="space-y-6">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
            Step 3: Advanced Options (Optional)
          </h2>

          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="factory">
              Factory Address
            </label>
            <input
              id="factory"
              type="text"
              value={config.factoryAddress}
              onChange={(e) =>
                setConfig((c) => ({ ...c, factoryAddress: e.target.value }))
              }
              placeholder="Leave empty for default"
              className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="salt">
              Salt (CREATE2)
            </label>
            <input
              id="salt"
              type="text"
              value={config.salt}
              onChange={(e) =>
                setConfig((c) => ({ ...c, salt: e.target.value }))
              }
              placeholder="Leave empty for random"
              className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => setStep('config')}
              className="flex-1 rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent"
            >
              Back
            </button>
            <button
              onClick={() => setStep('deploy')}
              className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Review & Deploy
            </button>
          </div>
        </section>
      )}

      {/* Step 4: Deploy */}
      {step === 'deploy' && !deployedAddress && (
        <section className="space-y-6">
          <h2 className="text-sm font-medium uppercase tracking-wider text-muted-foreground">
            Step 4: Deploy
          </h2>

          <div className="rounded-lg border border-border bg-card p-6 space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Type</span>
              <span className="font-mono">
                {config.type === 'safe' ? 'Gnosis Safe' : 'ERC-4337'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Chain</span>
              <span>
                {config.chain} ({config.chainId})
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Threshold</span>
              <span className="font-mono">
                {config.threshold}-of-{config.owners.filter(Boolean).length}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Owners</span>
              <ul className="mt-1 space-y-1">
                {config.owners.filter(Boolean).map((o, i) => (
                  <li key={i} className="truncate font-mono text-xs">
                    {o}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}

          <div className="flex gap-3">
            <button
              onClick={() => setStep('advanced')}
              disabled={deploying}
              className="flex-1 rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"
            >
              Back
            </button>
            <button
              onClick={handleDeploy}
              disabled={deploying}
              className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {deploying ? 'Deploying...' : 'Deploy'}
            </button>
          </div>

          {deploying && (
            <div className="flex items-center justify-center gap-3 py-4">
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              <span className="text-sm text-muted-foreground">
                Deploying contract...
              </span>
            </div>
          )}
        </section>
      )}

      {/* Success */}
      {deployedAddress && (
        <section className="rounded-lg border border-green-600/30 bg-green-600/10 p-6 text-center space-y-4">
          <p className="text-lg font-medium text-green-500">
            Smart Wallet Deployed
          </p>
          <p className="truncate font-mono text-sm text-green-500/80">
            {deployedAddress}
          </p>
          <button
            onClick={() =>
              router.push(`/wallets/${params.id}/smart-wallets`)
            }
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            View Smart Wallets
          </button>
        </section>
      )}
    </div>
  )
}
