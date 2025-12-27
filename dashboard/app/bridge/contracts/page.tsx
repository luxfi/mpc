'use client'

import { useState } from 'react'
import Link from 'next/link'
import { Nav } from '@/components/layout/nav'

const defaultContracts = [
  { chain: 'ethereum', name: 'Ethereum', token: 'WLUX', address: '', bridgeRole: false },
  { chain: 'lux', name: 'Lux Network', token: 'LUX', address: '', bridgeRole: false },
  { chain: 'bsc', name: 'BNB Chain', token: 'WLUX', address: '', bridgeRole: false },
  { chain: 'base', name: 'Base', token: 'WLUX', address: '', bridgeRole: false },
  { chain: 'arbitrum', name: 'Arbitrum', token: 'WLUX', address: '', bridgeRole: false },
  { chain: 'polygon', name: 'Polygon', token: 'WLUX', address: '', bridgeRole: false },
]

export default function BridgeContractsPage() {
  const [contracts, setContracts] = useState(defaultContracts)

  function handleAddressChange(chain: string, address: string) {
    setContracts(prev => prev.map(c =>
      c.chain === chain ? { ...c, address } : c
    ))
  }

  return (
    <>
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/bridge" className="hover:text-foreground">Bridge</Link>
          <span>/</span>
          <span>Contracts</span>
        </div>

        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight">Bridge Contracts</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Manage ERC20B bridge token contracts and BRIDGE_ROLE access control.
          </p>
        </div>

        <div className="mb-6 rounded-md border border-amber-500/30 bg-amber-500/5 p-4">
          <p className="text-sm text-amber-500">
            The MPC bridge-signer wallet needs BRIDGE_ROLE granted on each token contract to mint bridged tokens.
            Call <code className="rounded bg-muted px-1">grantBridge(address)</code> on each ERC20B contract with the MPC wallet address.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card">
          <div className="grid grid-cols-12 gap-4 border-b border-border px-6 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            <div className="col-span-2">Chain</div>
            <div className="col-span-1">Token</div>
            <div className="col-span-6">Contract Address</div>
            <div className="col-span-2">BRIDGE_ROLE</div>
            <div className="col-span-1"></div>
          </div>
          {contracts.map((contract) => (
            <div
              key={contract.chain}
              className="grid grid-cols-12 items-center gap-4 border-b border-border px-6 py-3 last:border-0"
            >
              <div className="col-span-2 text-sm font-medium">{contract.name}</div>
              <div className="col-span-1 font-mono text-xs text-muted-foreground">{contract.token}</div>
              <div className="col-span-6">
                <input
                  type="text"
                  value={contract.address}
                  onChange={(e) => handleAddressChange(contract.chain, e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="0x..."
                />
              </div>
              <div className="col-span-2">
                <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${
                  contract.bridgeRole
                    ? 'bg-green-500/10 text-green-500'
                    : 'bg-muted text-muted-foreground'
                }`}>
                  {contract.bridgeRole ? 'Granted' : 'Not granted'}
                </span>
              </div>
              <div className="col-span-1">
                {contract.address && !contract.bridgeRole && (
                  <button className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
                    Grant
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </main>
    </>
  )
}
