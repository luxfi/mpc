'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CreateWalletRequest, ReshareWalletRequest } from '@/lib/types'

const WALLETS_KEY = ['wallets'] as const

export function useWallets(vaultId: string) {
  return useQuery({
    queryKey: [...WALLETS_KEY, 'by-vault', vaultId],
    queryFn: () => api.listWallets(vaultId),
    enabled: !!vaultId,
  })
}

export function useWallet(id: string) {
  return useQuery({
    queryKey: [...WALLETS_KEY, id],
    queryFn: () => api.getWallet(id),
    enabled: !!id,
  })
}

export function useWalletAddresses(id: string) {
  return useQuery({
    queryKey: [...WALLETS_KEY, id, 'addresses'],
    queryFn: () => api.getWalletAddresses(id),
    enabled: !!id,
  })
}

export function useWalletHistory(id: string) {
  return useQuery({
    queryKey: [...WALLETS_KEY, id, 'history'],
    queryFn: () => api.getWalletHistory(id),
    enabled: !!id,
  })
}

export function useCreateWallet() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ vaultId, ...req }: CreateWalletRequest & { vaultId: string }) =>
      api.createWallet(vaultId, req),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: [...WALLETS_KEY, 'by-vault', variables.vaultId] })
    },
  })
}

export function useReshareWallet() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...req }: ReshareWalletRequest & { id: string }) =>
      api.reshareWallet(id, req),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: [...WALLETS_KEY, variables.id] })
    },
  })
}
