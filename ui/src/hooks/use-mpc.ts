import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'

export function useStatus() {
  return useQuery({ queryKey: ['mpc', 'status'], queryFn: api.getStatus })
}

export function useInfo() {
  return useQuery({ queryKey: ['mpc', 'info'], queryFn: api.getInfo })
}

export function useVaults() {
  return useQuery({ queryKey: ['mpc', 'vaults'], queryFn: api.listVaults })
}

export function useWallets(vaultId: string) {
  return useQuery({
    queryKey: ['mpc', 'wallets', vaultId],
    queryFn: () => api.listWallets(vaultId),
    enabled: !!vaultId,
  })
}

export function useTransactions(filters?: { status?: string; chain?: string }) {
  return useQuery({
    queryKey: ['mpc', 'transactions', filters],
    queryFn: () => api.listTransactions(filters),
  })
}

export function useOperations(filters?: { status?: string; walletId?: string; page?: number; perPage?: number }) {
  return useQuery({
    queryKey: ['mpc', 'operations', filters],
    queryFn: () => api.listOperations(filters),
    refetchInterval: 5000,
  })
}

export function useOperation(operationId: string) {
  return useQuery({
    queryKey: ['mpc', 'operation', operationId],
    queryFn: () => api.getOperation(operationId),
    enabled: !!operationId,
  })
}

export function useSessions(walletId: string) {
  return useQuery({
    queryKey: ['mpc', 'sessions', walletId],
    queryFn: () => api.listSessions(walletId),
    enabled: !!walletId,
  })
}

export function usePolicies() {
  return useQuery({ queryKey: ['mpc', 'policies'], queryFn: api.listPolicies })
}

export function useSettlements(filters?: { status?: string }) {
  return useQuery({
    queryKey: ['mpc', 'settlements', filters],
    queryFn: () => api.listSettlements(filters),
  })
}

export function useBridgeConfig() {
  return useQuery({ queryKey: ['mpc', 'bridge', 'config'], queryFn: api.getBridgeConfig })
}

export function useBridgeNetworks() {
  return useQuery({ queryKey: ['mpc', 'bridge', 'networks'], queryFn: api.listBridgeNetworks })
}

export function usePaymentRequests() {
  return useQuery({ queryKey: ['mpc', 'payments'], queryFn: api.listPaymentRequests })
}

export function useAudit() {
  return useQuery({ queryKey: ['mpc', 'audit'], queryFn: api.listAudit })
}

export function useWalletBackups(walletId: string) {
  return useQuery({
    queryKey: ['mpc', 'backup', walletId],
    queryFn: () => api.getWalletBackups(walletId),
    enabled: !!walletId,
  })
}

export function useUsers() {
  return useQuery({ queryKey: ['mpc', 'users'], queryFn: api.listUsers })
}

export function useAPIKeys() {
  return useQuery({ queryKey: ['mpc', 'api-keys'], queryFn: api.listAPIKeys })
}

export function useWebhooks() {
  return useQuery({ queryKey: ['mpc', 'webhooks'], queryFn: api.listWebhooks })
}

export function useWhitelist() {
  return useQuery({ queryKey: ['mpc', 'whitelist'], queryFn: api.listWhitelist })
}

export function useWebAuthnCredentials() {
  return useQuery({ queryKey: ['mpc', 'webauthn'], queryFn: api.listWebAuthnCredentials })
}
