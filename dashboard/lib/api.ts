// API client for Lux MPC backend (all routes from pkg/api/server.go)

import { getToken, getRefreshToken, setTokens, clearTokens } from './auth'
import type {
  AuthResponse,
  RegisterRequest,
  LoginRequest,
  MFARequiredResponse,
  Vault,
  CreateVaultRequest,
  UpdateVaultRequest,
  Wallet,
  WalletAddresses,
  CreateWalletRequest,
  ReshareWalletRequest,
  Transaction,
  TransactionFilters,
  CreateTransactionRequest,
  RejectTransactionRequest,
  Policy,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  AddressWhitelist,
  AddWhitelistRequest,
  Webhook,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  Subscription,
  CreateSubscriptionRequest,
  UpdateSubscriptionRequest,
  PaymentRequest,
  CreatePaymentRequestRequest,
  PayPaymentRequestRequest,
  SmartWallet,
  DeploySmartWalletRequest,
  ProposeSafeTxRequest,
  ExecuteSafeTxRequest,
  UserOperationRequest,
  User,
  InviteUserRequest,
  UpdateUserRequest,
  APIKey,
  APIKeyCreateResponse,
  CreateAPIKeyRequest,
  AuditEntry,
  ClusterStatus,
  InfoResponse,
} from './types'

export class APIError extends Error {
  constructor(
    public status: number,
    public body: { error: string },
  ) {
    super(body.error)
    this.name = 'APIError'
  }
}

export class APIClient {
  private baseURL: string
  private refreshing: Promise<void> | null = null

  constructor(baseURL?: string) {
    this.baseURL = baseURL ?? (process.env.NEXT_PUBLIC_API_URL || '/api/v1')
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    retry = true,
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    const token = getToken()
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    const res = await fetch(`${this.baseURL}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })

    // Handle 401 with automatic token refresh
    if (res.status === 401 && retry) {
      await this.tryRefresh()
      return this.request<T>(method, path, body, false)
    }

    if (res.status === 204) {
      return undefined as T
    }

    const data = await res.json()

    if (!res.ok) {
      throw new APIError(res.status, data)
    }

    return data as T
  }

  private async tryRefresh(): Promise<void> {
    // Deduplicate concurrent refresh attempts
    if (this.refreshing) {
      await this.refreshing
      return
    }

    this.refreshing = (async () => {
      const refreshToken = getRefreshToken()
      if (!refreshToken) {
        clearTokens()
        throw new APIError(401, { error: 'no refresh token' })
      }

      try {
        const res = await fetch(`${this.baseURL}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        })

        if (!res.ok) {
          clearTokens()
          throw new APIError(401, { error: 'refresh failed' })
        }

        const data: AuthResponse = await res.json()
        setTokens(data.access_token, data.refresh_token)
      } catch (err) {
        clearTokens()
        throw err
      }
    })()

    try {
      await this.refreshing
    } finally {
      this.refreshing = null
    }
  }

  private get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path)
  }

  private post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body)
  }

  private patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PATCH', path, body)
  }

  private del<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path)
  }

  // --- Auth ---

  async register(req: RegisterRequest): Promise<AuthResponse> {
    return this.post<AuthResponse>('/auth/register', req)
  }

  async login(req: LoginRequest): Promise<AuthResponse | MFARequiredResponse> {
    return this.post<AuthResponse | MFARequiredResponse>('/auth/login', req)
  }

  async refresh(refreshToken: string): Promise<AuthResponse> {
    return this.post<AuthResponse>('/auth/refresh', { refresh_token: refreshToken })
  }

  async mfaSetup(): Promise<{ secret: string; otpauth: string }> {
    return this.post('/auth/mfa/setup')
  }

  async mfaVerify(code: string): Promise<{ status: string }> {
    return this.post('/auth/mfa/verify', { code })
  }

  // --- Vaults ---

  async listVaults(): Promise<Vault[]> {
    return this.get<Vault[]>('/vaults')
  }

  async createVault(req: CreateVaultRequest): Promise<Vault> {
    return this.post<Vault>('/vaults', req)
  }

  async getVault(id: string): Promise<Vault> {
    return this.get<Vault>(`/vaults/${id}`)
  }

  async updateVault(id: string, req: UpdateVaultRequest): Promise<Vault> {
    return this.patch<Vault>(`/vaults/${id}`, req)
  }

  async deleteVault(id: string): Promise<void> {
    return this.del(`/vaults/${id}`)
  }

  // --- Wallets ---

  async listWallets(vaultId: string): Promise<Wallet[]> {
    return this.get<Wallet[]>(`/vaults/${vaultId}/wallets`)
  }

  async createWallet(vaultId: string, req: CreateWalletRequest): Promise<Wallet> {
    return this.post<Wallet>(`/vaults/${vaultId}/wallets`, req)
  }

  async getWallet(id: string): Promise<Wallet> {
    return this.get<Wallet>(`/wallets/${id}`)
  }

  async getWalletAddresses(id: string): Promise<WalletAddresses> {
    return this.get<WalletAddresses>(`/wallets/${id}/addresses`)
  }

  async reshareWallet(id: string, req: ReshareWalletRequest): Promise<{ status: string }> {
    return this.post(`/wallets/${id}/reshare`, req)
  }

  async getWalletHistory(id: string): Promise<Transaction[]> {
    return this.get<Transaction[]>(`/wallets/${id}/history`)
  }

  // --- Transactions ---

  async createTransaction(req: CreateTransactionRequest): Promise<Transaction> {
    return this.post<Transaction>('/transactions', req)
  }

  async listTransactions(filters?: TransactionFilters): Promise<Transaction[]> {
    const params = new URLSearchParams()
    if (filters?.status) params.set('status', filters.status)
    if (filters?.chain) params.set('chain', filters.chain)
    const qs = params.toString()
    return this.get<Transaction[]>(`/transactions${qs ? `?${qs}` : ''}`)
  }

  async getTransaction(id: string): Promise<Transaction> {
    return this.get<Transaction>(`/transactions/${id}`)
  }

  async approveTransaction(id: string): Promise<{ status: string }> {
    return this.post(`/transactions/${id}/approve`)
  }

  async rejectTransaction(id: string, req?: RejectTransactionRequest): Promise<{ status: string }> {
    return this.post(`/transactions/${id}/reject`, req)
  }

  // --- Policies ---

  async listPolicies(): Promise<Policy[]> {
    return this.get<Policy[]>('/policies')
  }

  async createPolicy(req: CreatePolicyRequest): Promise<Policy> {
    return this.post<Policy>('/policies', req)
  }

  async updatePolicy(id: string, req: UpdatePolicyRequest): Promise<Policy> {
    return this.patch<Policy>(`/policies/${id}`, req)
  }

  async deletePolicy(id: string): Promise<void> {
    return this.del(`/policies/${id}`)
  }

  // --- Whitelist ---

  async listWhitelist(): Promise<AddressWhitelist[]> {
    return this.get<AddressWhitelist[]>('/whitelist')
  }

  async addWhitelist(req: AddWhitelistRequest): Promise<AddressWhitelist> {
    return this.post<AddressWhitelist>('/whitelist', req)
  }

  async deleteWhitelist(id: string): Promise<void> {
    return this.del(`/whitelist/${id}`)
  }

  // --- Webhooks ---

  async listWebhooks(): Promise<Webhook[]> {
    return this.get<Webhook[]>('/webhooks')
  }

  async createWebhook(req: CreateWebhookRequest): Promise<Webhook> {
    return this.post<Webhook>('/webhooks', req)
  }

  async updateWebhook(id: string, req: UpdateWebhookRequest): Promise<Webhook> {
    return this.patch<Webhook>(`/webhooks/${id}`, req)
  }

  async deleteWebhook(id: string): Promise<void> {
    return this.del(`/webhooks/${id}`)
  }

  async testWebhook(id: string): Promise<{ status: string }> {
    return this.post(`/webhooks/${id}/test`)
  }

  // --- Subscriptions ---

  async listSubscriptions(): Promise<Subscription[]> {
    return this.get<Subscription[]>('/subscriptions')
  }

  async createSubscription(req: CreateSubscriptionRequest): Promise<Subscription> {
    return this.post<Subscription>('/subscriptions', req)
  }

  async getSubscription(id: string): Promise<Subscription> {
    return this.get<Subscription>(`/subscriptions/${id}`)
  }

  async updateSubscription(id: string, req: UpdateSubscriptionRequest): Promise<Subscription> {
    return this.patch<Subscription>(`/subscriptions/${id}`, req)
  }

  async deleteSubscription(id: string): Promise<void> {
    return this.del(`/subscriptions/${id}`)
  }

  async payNow(id: string): Promise<{ status: string; tx_id: string }> {
    return this.post(`/subscriptions/${id}/pay-now`)
  }

  // --- Payment Requests ---

  async createPaymentRequest(req: CreatePaymentRequestRequest): Promise<{
    payment_request: PaymentRequest
    payment_url: string
  }> {
    return this.post('/payment-requests', req)
  }

  async listPaymentRequests(): Promise<PaymentRequest[]> {
    return this.get<PaymentRequest[]>('/payment-requests')
  }

  async getPaymentRequest(id: string): Promise<PaymentRequest> {
    return this.get<PaymentRequest>(`/payment-requests/${id}`)
  }

  async payPaymentRequest(id: string, req: PayPaymentRequestRequest): Promise<{ status: string; tx_id: string }> {
    return this.post(`/payment-requests/${id}/pay`, req)
  }

  // --- Smart Wallets ---

  async deploySmartWallet(walletId: string, req: DeploySmartWalletRequest): Promise<SmartWallet> {
    return this.post<SmartWallet>(`/wallets/${walletId}/smart-wallet`, req)
  }

  async listSmartWallets(walletId: string): Promise<SmartWallet[]> {
    return this.get<SmartWallet[]>(`/wallets/${walletId}/smart-wallets`)
  }

  async getSmartWallet(id: string): Promise<SmartWallet> {
    return this.get<SmartWallet>(`/smart-wallets/${id}`)
  }

  async proposeSafeTx(id: string, req: ProposeSafeTxRequest): Promise<{ status: string; smart_wallet_id: string; to: string; value: string }> {
    return this.post(`/smart-wallets/${id}/propose`, req)
  }

  async executeSafeTx(id: string, req: ExecuteSafeTxRequest): Promise<{ status: string; safe_tx_hash: string }> {
    return this.post(`/smart-wallets/${id}/execute`, req)
  }

  async userOperation(id: string, req: UserOperationRequest): Promise<{ status: string; smart_wallet_id: string }> {
    return this.post(`/smart-wallets/${id}/user-operation`, req)
  }

  // --- Users & Teams ---

  async listUsers(): Promise<User[]> {
    return this.get<User[]>('/users')
  }

  async inviteUser(req: InviteUserRequest): Promise<User> {
    return this.post<User>('/users', req)
  }

  async updateUser(id: string, req: UpdateUserRequest): Promise<User> {
    return this.patch<User>(`/users/${id}`, req)
  }

  async deleteUser(id: string): Promise<void> {
    return this.del(`/users/${id}`)
  }

  // --- API Keys ---

  async listAPIKeys(): Promise<APIKey[]> {
    return this.get<APIKey[]>('/api-keys')
  }

  async createAPIKey(req: CreateAPIKeyRequest): Promise<APIKeyCreateResponse> {
    return this.post<APIKeyCreateResponse>('/api-keys', req)
  }

  async deleteAPIKey(id: string): Promise<void> {
    return this.del(`/api-keys/${id}`)
  }

  // --- Audit ---

  async listAudit(): Promise<AuditEntry[]> {
    return this.get<AuditEntry[]>('/audit')
  }

  // --- Status & Info ---

  async getStatus(): Promise<ClusterStatus> {
    return this.get<ClusterStatus>('/status')
  }

  async getInfo(): Promise<InfoResponse> {
    return this.get<InfoResponse>('/info')
  }
}

// Singleton instance
export const api = new APIClient()
