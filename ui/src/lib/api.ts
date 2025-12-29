// Typed API client for MPC backend.
//
// Two surfaces: the spec'd Liquidity MPC namespace at /v1/mpc/* and the
// platform-internal /v1/* (auth, users, webhooks, api-keys, whitelist,
// webauthn). Everything authenticates with the bearer JWT in localStorage.

const ROOT = '/v1'
const MPC = '/v1/mpc'

export class APIError extends Error {
  constructor(public status: number, public body: { error?: string }) {
    super(body.error ?? `HTTP ${status}`)
    this.name = 'APIError'
  }
}

const TOKEN_KEY = 'mpc_token'
const REFRESH_KEY = 'mpc_refresh'
const USER_KEY = 'mpc_user'

export const auth = {
  token: (): string | null => localStorage.getItem(TOKEN_KEY),
  refresh: (): string | null => localStorage.getItem(REFRESH_KEY),
  user: (): { id: string; org_id: string; role: string; email: string } | null => {
    const raw = localStorage.getItem(USER_KEY)
    return raw ? JSON.parse(raw) : null
  },
  set: (token: string, refresh: string, user: { id: string; org_id: string; role: string; email: string }) => {
    localStorage.setItem(TOKEN_KEY, token)
    localStorage.setItem(REFRESH_KEY, refresh)
    localStorage.setItem(USER_KEY, JSON.stringify(user))
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(REFRESH_KEY)
    localStorage.removeItem(USER_KEY)
  },
}

async function request<T>(method: string, fullPath: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const t = auth.token()
  if (t) headers['Authorization'] = `Bearer ${t}`

  const res = await fetch(fullPath, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (res.status === 204) return undefined as T

  // 401: token dead, force re-login
  if (res.status === 401 && fullPath !== `${ROOT}/auth/login`) {
    auth.clear()
    if (typeof window !== 'undefined') window.location.hash = '#/login'
  }

  const text = await res.text()
  const data = text ? JSON.parse(text) : {}
  if (!res.ok) throw new APIError(res.status, data)
  return data as T
}

const get = <T>(p: string) => request<T>('GET', p)
const post = <T>(p: string, b?: unknown) => request<T>('POST', p, b)
const patch = <T>(p: string, b?: unknown) => request<T>('PATCH', p, b)
const del = <T>(p: string) => request<T>('DELETE', p)

// =================================================================
// Types — matching Go backend models
// =================================================================

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

export interface OperationApproval {
  approverId: string
  approvedAt: string
  notes?: string
}

export interface Operation {
  operationId: string
  walletId: string
  kind: string
  payload?: Record<string, unknown>
  status: string
  approvers?: string[]
  approvals?: OperationApproval[]
  rejectionReason?: string
  result?: Record<string, string>
  createdAt: string
  completedAt?: string
}

export interface OperationsPage {
  items: Operation[]
  page: number
  perPage: number
  totalItems: number
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

export interface User {
  id: string
  createdAt: string
  orgId: string
  email: string
  role: string
}

export interface APIKey {
  id: string
  name: string
  keyPrefix: string
  permissions: string[]
  expiresAt?: string | null
  lastUsedAt?: string | null
  createdAt: string
}

export interface APIKeyCreated {
  id: string
  name: string
  key: string
  key_prefix: string
  permissions: string[]
  created_at: string
}

export interface Webhook {
  id: string
  org_id: string
  url: string
  secret: string
  events: string[]
  enabled: boolean
  created_at: string
}

export interface WhitelistEntry {
  id: string
  org_id: string
  vault_id?: string | null
  address: string
  chain: string
  label?: string | null
  created_at: string
}

export interface WebAuthnCredential {
  id: string
  device_name?: string | null
  created_at: string
}

export interface Session {
  sessionId: string
  walletId: string
  grantedTo?: string
  scopes?: string[]
  valueLimit?: string
  operationLimit?: number
  status: string
  createdAt: string
  expiresAt: string
  revokedAt?: string
}

export interface LoginResponse {
  user_id: string
  org_id: string
  role: string
  email?: string
  access_token: string
  refresh_token: string
  mfa_required?: boolean
}

// =================================================================
// API methods
// =================================================================

export const api = {
  // -------- Auth (no /mpc prefix; raw v1) --------
  login: (email: string, password: string, mfa_code?: string) =>
    post<LoginResponse>(`${ROOT}/auth/login`, { email, password, mfa_code }),
  refresh: (refresh_token: string) =>
    post<{ access_token: string; refresh_token: string }>(`${ROOT}/auth/refresh`, { refresh_token }),
  register: (email: string, password: string, org_name: string) =>
    post<LoginResponse>(`${ROOT}/auth/register`, { email, password, org_name }),

  // -------- Status --------
  getStatus: () => get<ClusterStatus>(`${MPC}/status`),
  getInfo: () => get<InfoResponse>(`${MPC}/info`),

  // -------- Vaults --------
  listVaults: () => get<Vault[]>(`${MPC}/vaults`),
  createVault: (req: { name: string; description?: string }) =>
    post<Vault>(`${MPC}/vaults`, req),
  deleteVault: (id: string) => del<void>(`${MPC}/vaults/${id}`),

  // -------- Wallets --------
  listWallets: (vaultId: string) => get<Wallet[]>(`${MPC}/vaults/${vaultId}/wallets`),
  createWallet: (vaultId: string, req?: { name?: string; key_type?: string; protocol?: string }) =>
    post<Wallet>(`${MPC}/vaults/${vaultId}/wallets`, req),
  getWalletBackups: (walletId: string) =>
    get<WalletBackup[]>(`${MPC}/wallets/${walletId}/backup`),

  // -------- Transactions / Operations --------
  listTransactions: (filters?: { status?: string; chain?: string }) => {
    const params = new URLSearchParams()
    if (filters?.status) params.set('status', filters.status)
    if (filters?.chain) params.set('chain', filters.chain)
    const qs = params.toString()
    return get<Transaction[]>(`${MPC}/transactions${qs ? `?${qs}` : ''}`)
  },

  listOperations: (filters?: { status?: string; walletId?: string; page?: number; perPage?: number }) => {
    const params = new URLSearchParams()
    if (filters?.status) params.set('status', filters.status)
    if (filters?.walletId) params.set('walletId', filters.walletId)
    if (filters?.page) params.set('page', String(filters.page))
    if (filters?.perPage) params.set('perPage', String(filters.perPage))
    const qs = params.toString()
    return get<OperationsPage>(`${MPC}/operations${qs ? `?${qs}` : ''}`)
  },
  getOperation: (id: string) => get<Operation>(`${MPC}/operations/${id}`),
  approveOperation: (id: string, notes?: string) =>
    post<Operation>(`${MPC}/operations/${id}/approve`, { notes: notes ?? '' }),
  rejectOperation: (id: string, reason: string) =>
    post<Operation>(`${MPC}/operations/${id}/reject`, { reason }),

  // -------- Sessions (per-wallet signing grants) --------
  listSessions: (walletId: string) =>
    get<{ items: Session[] }>(`${MPC}/wallets/${walletId}/sessions`),
  createSession: (walletId: string, req: {
    grantedTo?: string
    scopes: string[]
    valueLimit?: string
    operationLimit?: number
    expiresAt: string
  }) => post<Session>(`${MPC}/wallets/${walletId}/sessions`, req),
  revokeSession: (walletId: string, sessionId: string) =>
    del<void>(`${MPC}/wallets/${walletId}/sessions/${sessionId}`),

  // -------- Policies --------
  listPolicies: () => get<Policy[]>(`${MPC}/policies`),
  createPolicy: (req: {
    name: string
    action: string
    priority: number
    conditions: Record<string, unknown>
    required_approvers: number
    approver_roles: string[]
  }) => post<Policy>(`${MPC}/policies`, req),
  updatePolicy: (id: string, req: { enabled?: boolean }) =>
    patch<Policy>(`${MPC}/policies/${id}`, req),
  deletePolicy: (id: string) => del<void>(`${MPC}/policies/${id}`),

  // -------- Settlements --------
  listSettlements: (filters?: { status?: string }) => {
    const params = new URLSearchParams()
    if (filters?.status) params.set('status', filters.status)
    const qs = params.toString()
    return get<Settlement[]>(`${MPC}/settlements${qs ? `?${qs}` : ''}`)
  },

  // -------- Bridge --------
  getBridgeConfig: () => get<BridgeConfig>(`${MPC}/bridge/config`),
  listBridgeNetworks: () => get<BridgeNetwork[]>(`${MPC}/bridge/networks`),

  // -------- Payments --------
  listPaymentRequests: () => get<PaymentRequest[]>(`${MPC}/payment-requests`),

  // -------- Audit --------
  listAudit: () => get<AuditEntry[]>(`${MPC}/audit`),

  // -------- Users --------
  listUsers: () => get<User[]>(`${ROOT}/users`),
  inviteUser: (req: { email: string; password: string; role?: string }) =>
    post<User>(`${ROOT}/users`, req),
  updateUser: (id: string, req: { role?: string }) =>
    patch<User>(`${ROOT}/users/${id}`, req),
  deleteUser: (id: string) => del<void>(`${ROOT}/users/${id}`),

  // -------- API Keys --------
  listAPIKeys: () => get<APIKey[]>(`${ROOT}/api-keys`),
  createAPIKey: (req: { name: string; permissions?: string[] }) =>
    post<APIKeyCreated>(`${ROOT}/api-keys`, req),
  deleteAPIKey: (id: string) => del<void>(`${ROOT}/api-keys/${id}`),

  // -------- Webhooks --------
  listWebhooks: () => get<Webhook[]>(`${ROOT}/webhooks`),
  createWebhook: (req: { url: string; events: string[]; secret: string }) =>
    post<Webhook>(`${ROOT}/webhooks`, req),
  updateWebhook: (id: string, req: { url?: string; events?: string[]; enabled?: boolean }) =>
    patch<Webhook>(`${ROOT}/webhooks/${id}`, req),
  deleteWebhook: (id: string) => del<void>(`${ROOT}/webhooks/${id}`),
  testWebhook: (id: string) =>
    post<{ status: string }>(`${ROOT}/webhooks/${id}/test`),

  // -------- Whitelist (allowlist for destinations) --------
  listWhitelist: () => get<WhitelistEntry[]>(`${ROOT}/whitelist`),
  addWhitelist: (req: { address: string; chain: string; label?: string; vault_id?: string }) =>
    post<WhitelistEntry>(`${ROOT}/whitelist`, req),
  deleteWhitelist: (id: string) => del<void>(`${ROOT}/whitelist/${id}`),

  // -------- WebAuthn --------
  listWebAuthnCredentials: () => get<WebAuthnCredential[]>(`${ROOT}/webauthn/credentials`),
  deleteWebAuthnCredential: (id: string) => del<void>(`${ROOT}/webauthn/credentials/${id}`),
  webAuthnRegisterBegin: () =>
    post<WebAuthnRegisterOptions>(`${ROOT}/webauthn/register/begin`),
  webAuthnRegisterComplete: (body: WebAuthnRegisterComplete) =>
    post<{ status: string; credential_id: string }>(`${ROOT}/webauthn/register/complete`, body),
  webAuthnVerify: (body: WebAuthnVerify) =>
    post<{ status: string; biometric: boolean; signing_started: boolean; approvals: number; required: number }>(
      `${ROOT}/webauthn/verify`, body,
    ),
}

// WebAuthn ceremony types — server-shaped, not browser-shaped.
export interface WebAuthnRegisterOptions {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  pubKeyCredParams: { type: string; alg: number }[]
  timeout: number
  attestation: string
  authenticatorSelection: {
    authenticatorAttachment: string
    userVerification: string
    residentKey: string
  }
  credential_id: string
}

export interface WebAuthnRegisterComplete {
  credential_id: string
  id: string
  rawId: string
  type: string
  response: {
    attestationObject: string
    clientDataJSON: string
  }
  device_name: string
}

export interface WebAuthnVerify {
  transaction_id: string
  credential_id: string
  authenticator_data: string
  client_data_json: string
  signature: string
}
