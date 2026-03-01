// JWT token management via localStorage

const ACCESS_TOKEN_KEY = 'lux_mpc_access_token'
const REFRESH_TOKEN_KEY = 'lux_mpc_refresh_token'
const USER_EMAIL_KEY = 'lux_mpc_user_email'

export function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(ACCESS_TOKEN_KEY)
}

export function getRefreshToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(REFRESH_TOKEN_KEY)
}

export function setTokens(accessToken: string, refreshToken: string): void {
  if (typeof window === 'undefined') return
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken)
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
  // Set session cookie so Next.js middleware can enforce auth on server side
  document.cookie = 'lux_mpc_session=1; path=/; SameSite=Strict; Secure'
}

export function setUserEmail(email: string): void {
  if (typeof window === 'undefined') return
  localStorage.setItem(USER_EMAIL_KEY, email)
}

export function getUserEmail(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(USER_EMAIL_KEY)
}

export function clearTokens(): void {
  if (typeof window === 'undefined') return
  localStorage.removeItem(ACCESS_TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
  localStorage.removeItem(USER_EMAIL_KEY)
  // Clear session cookie so middleware redirects to /login immediately
  document.cookie = 'lux_mpc_session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Strict'
}

export function isAuthenticated(): boolean {
  return getToken() !== null
}
