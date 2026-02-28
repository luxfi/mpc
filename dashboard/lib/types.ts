// Types matching Go backend models (pkg/db/models.go + pkg/api/server.go)

// --- Core entities ---

export interface Organization {
  id: string
  name: string
  slug: string
  created_at: string
}

export interface User {
  id: string
  org_id: string
  email: string
  role: string // owner | admin | signer | viewer
  created_at: string
}

export interface APIKey {
  id: string
  org_id: string
  name: string
  key_prefix: string
  permissions: string[]
  created_at: string
  expires_at?: string | null
  last_used_at?: string | null
}

export interface APIKeyCreateResponse extends APIKey {
  key: string // full key, returned only on creation
}

export interface Vault {
  id: string
  org_id: string
  name: string
  description?: string | null
  app_id?: string | null
  created_at: string
}

export interface Wallet {
  id: string
  vault_id: string
  org_id: string
  wallet_id: string
  name?: string | null
  key_type: string // secp256k1 | ed25519
  ecdsa_pubkey?: string | null
  eddsa_pubkey?: string | null
  eth_address?: string | null
  btc_address?: string | null
  sol_address?: string | null
  threshold: number
  participants: string[]
  version: number
  status: string // active | resharing | archived
  created_by?: string | null
  created_at: string
}

export interface WalletAddresses {
  ethereum?: string
  bitcoin?: string
  solana?: string
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
  signature_r?: string | null
  signature_s?: string | null
  signature_eddsa?: string | null
  status: string // pending | pending_approval | approved | signing | signed | broadcast | failed | rejected
  initiated_by?: string | null
  approved_by?: string[]
  rejected_by?: string | null
  rejection_reason?: string | null
  created_at: string
  signed_at?: string | null
  broadcast_at?: string | null
}

export interface Policy {
  id: string
  org_id: string
  vault_id?: string | null
  name: string
  priority: number
  action: string // approve | deny | require_approval
  conditions: Record<string, unknown>
  required_approvers: number
  approver_roles: string[]
  enabled: boolean
  created_at: string
}

export interface AddressWhitelist {
  id: string
  org_id: string
  vault_id?: string | null
  address: string
  chain: string
  label?: string | null
  created_by?: string | null
  created_at: string
}

export interface AuditEntry {
  id: number
  org_id: string
  user_id?: string | null
  action: string
  resource_type?: string | null
  resource_id?: string | null
  details?: Record<string, unknown> | null
  ip_address?: string | null
  created_at: string
}

export interface Webhook {
  id: string
  org_id: string
  url: string
  events: string[]
  enabled: boolean
  created_at: string
}

export interface Subscription {
  id: string
  org_id: string
  wallet_id?: string | null
  name: string
  provider_name?: string | null
  recipient_address: string
  chain: string
  token?: string | null
  amount: string
  currency: string
  interval: string // daily | weekly | monthly | yearly
  next_payment_at: string
  last_payment_at?: string | null
  last_tx_id?: string | null
  status: string // active | paused | cancelled | failed
  max_retries: number
  retry_count: number
  require_balance: boolean
  created_by?: string | null
  cancelled_by?: string | null
  created_at: string
  cancelled_at?: string | null
}

export interface PaymentRequest {
  id: string
  org_id: string
  wallet_id?: string | null
  request_token: string
  merchant_name?: string | null
  recipient_address: string
  chain: string
  token?: string | null
  amount: string
  memo?: string | null
  status: string // pending | paid | expired | cancelled
  expires_at?: string | null
  paid_tx_id?: string | null
  created_at: string
}

export interface SmartWallet {
  id: string
  wallet_id: string
  org_id: string
  chain: string
  contract_address: string
  wallet_type: string // safe | erc4337
  factory_address?: string | null
  entrypoint_address?: string | null
  salt?: string | null
  owners: string[]
  threshold: number
  status: string // active | deploying | archived
  deployed_at?: string | null
  created_at: string
}

// --- MPC cluster types (pkg/api/server.go) ---

export interface ClusterStatus {
  node_id: string
  mode: string
  expected_peers: number
  connected_peers: number
  ready: boolean
  threshold: number
  version: string
}

export interface KeygenResult {
  wallet_id: string
  ecdsa_pub_key: string
  eddsa_pub_key: string
  eth_address: string
}

export interface SignResult {
  r?: string
  s?: string
  signature?: string
}

export interface InfoResponse {
  name: string
  version: string
  supported_chains: string[]
  key_types: string[]
  protocols: string[]
}

// --- Auth request/response types ---

export interface RegisterRequest {
  org_name: string
  email: string
  password: string
}

export interface LoginRequest {
  email: string
  password: string
  mfa_code?: string
}

export interface RefreshRequest {
  refresh_token: string
}

export interface AuthResponse {
  user_id: string
  org_id: string
  role?: string
  access_token: string
  refresh_token: string
}

export interface MFARequiredResponse {
  mfa_required: true
}

export interface ErrorResponse {
  error: string
}

// --- Request body types for create/update ---

export interface CreateVaultRequest {
  name: string
  description?: string
  app_id?: string
}

export interface UpdateVaultRequest {
  name?: string
  description?: string
}

export interface CreateWalletRequest {
  name?: string
  key_type?: string // secp256k1 | ed25519
}

export interface ReshareWalletRequest {
  new_threshold: number
  new_participants: string[]
}

export interface CreateTransactionRequest {
  wallet_id: string
  tx_type: string
  chain: string
  to_address: string
  amount: string
  token?: string
  raw_tx?: string
}

export interface RejectTransactionRequest {
  reason?: string
}

export interface CreatePolicyRequest {
  vault_id?: string
  name: string
  priority: number
  action: string
  conditions: Record<string, unknown>
  required_approvers: number
  approver_roles: string[]
}

export interface UpdatePolicyRequest {
  name?: string
  priority?: number
  action?: string
  conditions?: Record<string, unknown>
  required_approvers?: number
  enabled?: boolean
}

export interface AddWhitelistRequest {
  vault_id?: string
  address: string
  chain: string
  label?: string
}

export interface CreateWebhookRequest {
  url: string
  events: string[]
  secret: string
}

export interface UpdateWebhookRequest {
  url?: string
  events?: string[]
  enabled?: boolean
}

export interface CreateSubscriptionRequest {
  wallet_id: string
  name: string
  provider_name?: string
  recipient_address: string
  chain: string
  token?: string
  amount: string
  currency?: string
  interval: string
  require_balance?: boolean
}

export interface UpdateSubscriptionRequest {
  status?: string
  amount?: string
}

export interface CreatePaymentRequestRequest {
  wallet_id?: string
  merchant_name?: string
  recipient_address: string
  chain: string
  token?: string
  amount: string
  memo?: string
  expires_in_hours?: number
}

export interface PayPaymentRequestRequest {
  wallet_id: string
}

export interface DeploySmartWalletRequest {
  chain: string
  wallet_type: string // safe | erc4337
  factory_address?: string
  entrypoint_address?: string
  salt?: string
  owners: string[]
  threshold: number
}

export interface ProposeSafeTxRequest {
  to: string
  value: string
  data?: string
}

export interface ExecuteSafeTxRequest {
  safe_tx_hash: string
}

export interface UserOperationRequest {
  call_data: string
  value?: string
}

export interface InviteUserRequest {
  email: string
  role?: string
  password: string
}

export interface UpdateUserRequest {
  role?: string
}

export interface CreateAPIKeyRequest {
  name: string
  permissions?: string[]
}

export interface TransactionFilters {
  status?: string
  chain?: string
}
