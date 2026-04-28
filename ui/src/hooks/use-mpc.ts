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
