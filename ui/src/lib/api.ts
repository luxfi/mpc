// Typed API client for MPC backend — all paths relative to /v1/mpc

const BASE = '/v1/mpc'

export class APIError extends Error {
  constructor(public status: number, public body: { error: string }) {
    super(body.error)
    this.name = 'APIError'
  }
}

function token(): string | null {
  return localStorage.getItem('mpc_token')
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const t = token()
  if (t) headers['Authorization'] = `Bearer ${t}`

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (res.status === 204) return undefined as T

  const data = await res.json()
  if (!res.ok) throw new APIError(res.status, data)
  return data as T
}

function get<T>(path: string): Promise<T> { return request<T>('GET', path) }
function post<T>(path: string, body?: unknown): Promise<T> { return request<T>('POST', path, body) }
function patch<T>(path: string, body?: unknown): Promise<T> { return request<T>('PATCH', path, body) }
function del<T>(path: string): Promise<T> { return request<T>('DELETE', path) }

// --- Types (matching Go backend models) ---

export interface ClusterStatus {
  node_id: string
  mode: string
  expected_peers: number
  connected_peers: number
  ready: boolean
  threshold: number
  version: string
}

export interface InfoResponse {
  name: string
  version: string
  supported_chains: string[]
  key_types: string[]
  protocols: string[]
}

export interface Vault {
  id: string
  org_id: string
  name: string
  description?: string | null
  created_at: string
}

export interface Wallet {
  id: string
  vault_id: string
  org_id: string
  wallet_id: string
  name?: string | null
  key_type: string
  protocol?: string
  ecdsa_pubkey?: string | null
  eddsa_pubkey?: string | null
  eth_address?: string | null
  btc_address?: string | null
  sol_address?: string | null
  threshold: number
  participants: string[]
  version: number
  status: string
  created_at: string
}

export interface Transaction {
  id: string
  org_id: string
  wallet_id?: string | null
  tx_type: string
  chain: string
  to_address?: string | null
  amount?: string | null
  token?: string | null
  tx_hash?: string | null
  status: string
  created_at: string
}

export interface Policy {
  id: string
  org_id: string
  vault_id?: string | null
  name: string
  priority: number
  action: string
  conditions: Record<string, unknown>
  required_approvers: number
  approver_roles: string[]
  enabled: boolean
  created_at: string
}

export interface Settlement {
  id: string
  org_id: string
  intent_id: string
  match_id?: string | null
  settlement_tx_hash?: string | null
  hsm_signatures?: { signer_id: string; key_id: string; signature: string; provider: string; signed_at: string }[]
  transfer_agency_verified: boolean
  status: string
  created_at: string
}

export interface PaymentRequest {
  id: string
  org_id: string
  merchant_name?: string | null
  recipient_address: string
  chain: string
  token?: string | null
  amount: string
  status: string
  created_at: string
}

export interface AuditEntry {
  id: number
  org_id: string
  user_id?: string | null
  action: string
  resource_type?: string | null
  resource_id?: string | null
  ip_address?: string | null
  created_at: string
}

export interface WalletBackup {
  id: string
  wallet_id: string
  backup_id: string
  threshold: number
  total_shards: number
  shards?: { index: number; destination: string; created_at: string; verified_at?: string | null }[]
  status: string
  created_at: string
}

export interface BridgeNetwork {
  chain: string
  name: string
  type: string
  deposit: boolean
  withdrawal: boolean
}

export interface BridgeConfig {
  signingWalletId?: string
  feeRateBps: number
  depositsEnabled: boolean
  withdrawalsEnabled: boolean
}

// --- API methods ---

export const api = {
  // Status
  getStatus: () => get<ClusterStatus>('/status'),
  getInfo: () => get<InfoResponse>('/info'),

  // Vaults
  listVaults: () => get<Vault[]>('/vaults'),
  createVault: (req: { name: string; description?: string }) => post<Vault>('/vaults', req),
  deleteVault: (id: string) => del(`/vaults/${id}`),

  // Wallets
  listWallets: (vaultId: string) => get<Wallet[]>(`/vaults/${vaultId}/wallets`),
  createWallet: (vaultId: string, req?: { name?: string; key_type?: string; protocol?: string }) =>
    post<Wallet>(`/vaults/${vaultId}/wallets`, req),
  getWalletBackups: (walletId: string) => get<WalletBackup[]>(`/wallets/${walletId}/backup`),

  // Transactions
  listTransactions: (filters?: { status?: string; chain?: string }) => {
    const params = new URLSearchParams()
    if (filters?.status) params.set('status', filters.status)
    if (filters?.chain) params.set('chain', filters.chain)
    const qs = params.toString()
    return get<Transaction[]>(`/transactions${qs ? `?${qs}` : ''}`)
  },

  // Policies
  listPolicies: () => get<Policy[]>('/policies'),
  createPolicy: (req: {
    name: string
    action: string
    priority: number
    conditions: Record<string, unknown>
    required_approvers: number
    approver_roles: string[]
  }) => post<Policy>('/policies', req),
  updatePolicy: (id: string, req: { enabled?: boolean }) => patch<Policy>(`/policies/${id}`, req),
  deletePolicy: (id: string) => del(`/policies/${id}`),

  // Settlements
  listSettlements: (filters?: { status?: string }) => {
    const params = new URLSearchParams()
    if (filters?.status) params.set('status', filters.status)
    const qs = params.toString()
    return get<Settlement[]>(`/settlements${qs ? `?${qs}` : ''}`)
  },

  // Bridge
  getBridgeConfig: () => get<BridgeConfig>('/bridge/config'),
  listBridgeNetworks: () => get<BridgeNetwork[]>('/bridge/networks'),

  // Payments
  listPaymentRequests: () => get<PaymentRequest[]>('/payment-requests'),

  // Audit
  listAudit: () => get<AuditEntry[]>('/audit'),
}
