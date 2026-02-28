'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { TransactionFilters, CreateTransactionRequest, RejectTransactionRequest } from '@/lib/types'

const TX_KEY = ['transactions'] as const

export function useTransactions(filters?: TransactionFilters) {
  return useQuery({
    queryKey: [...TX_KEY, filters ?? {}],
    queryFn: () => api.listTransactions(filters),
  })
}

export function useTransaction(id: string) {
  return useQuery({
    queryKey: [...TX_KEY, id],
    queryFn: () => api.getTransaction(id),
    enabled: !!id,
  })
}

export function useCreateTransaction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: CreateTransactionRequest) => api.createTransaction(req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: TX_KEY })
    },
  })
}

export function useApproveTransaction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.approveTransaction(id),
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: TX_KEY })
      qc.invalidateQueries({ queryKey: [...TX_KEY, id] })
    },
  })
}

export function useRejectTransaction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...req }: RejectTransactionRequest & { id: string }) =>
      api.rejectTransaction(id, req),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: TX_KEY })
      qc.invalidateQueries({ queryKey: [...TX_KEY, variables.id] })
    },
  })
}
