'use client'

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { setTokens, clearTokens } from '@/lib/auth'
import type { LoginRequest, RegisterRequest } from '@/lib/types'

export function useLogin() {
  return useMutation({
    mutationFn: (req: LoginRequest) => api.login(req),
    onSuccess: (data) => {
      if ('access_token' in data) {
        setTokens(data.access_token, data.refresh_token)
      }
    },
  })
}

export function useRegister() {
  return useMutation({
    mutationFn: (req: RegisterRequest) => api.register(req),
    onSuccess: (data) => {
      setTokens(data.access_token, data.refresh_token)
    },
  })
}

export function useLogout() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      clearTokens()
    },
    onSuccess: () => {
      qc.invalidateQueries()
    },
  })
}
