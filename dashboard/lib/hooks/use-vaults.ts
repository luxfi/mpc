'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CreateVaultRequest, UpdateVaultRequest } from '@/lib/types'

const VAULTS_KEY = ['vaults'] as const

export function useVaults() {
  return useQuery({
    queryKey: VAULTS_KEY,
    queryFn: () => api.listVaults(),
  })
}

export function useVault(id: string) {
  return useQuery({
    queryKey: [...VAULTS_KEY, id],
    queryFn: () => api.getVault(id),
    enabled: !!id,
  })
}

export function useCreateVault() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: CreateVaultRequest) => api.createVault(req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: VAULTS_KEY })
    },
  })
}

export function useUpdateVault() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...req }: UpdateVaultRequest & { id: string }) =>
      api.updateVault(id, req),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: VAULTS_KEY })
      qc.invalidateQueries({ queryKey: [...VAULTS_KEY, variables.id] })
    },
  })
}

export function useDeleteVault() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteVault(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: VAULTS_KEY })
    },
  })
}
