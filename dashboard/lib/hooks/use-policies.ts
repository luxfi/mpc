'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CreatePolicyRequest, UpdatePolicyRequest } from '@/lib/types'

const POLICIES_KEY = ['policies'] as const

export function usePolicies() {
  return useQuery({
    queryKey: POLICIES_KEY,
    queryFn: () => api.listPolicies(),
  })
}

export function useCreatePolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: CreatePolicyRequest) => api.createPolicy(req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: POLICIES_KEY })
    },
  })
}

export function useUpdatePolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...req }: UpdatePolicyRequest & { id: string }) =>
      api.updatePolicy(id, req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: POLICIES_KEY })
    },
  })
}

export function useDeletePolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deletePolicy(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: POLICIES_KEY })
    },
  })
}
