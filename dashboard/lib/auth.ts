// The MPC API's own JWT, and the server-visible session flag.
//
// TWO tokens, two audiences, said plainly:
//   * the IAM access token — the SESSION. Owned by @hanzo/iam (PKCE, one
//     refresh timer) under its own `hanzo_iam_*` keys, and read by the shared
//     @luxfi/ui chrome. Nothing in this file touches it.
//   * the MPC API JWT below — minted FROM the IAM token by `POST /auth/oidc`,
//     and only good against the MPC API.
//
// `markSession` is the one bit Next middleware can see: sessionStorage is
// invisible to the server, so the login writes a flag cookie the matcher reads.
// It is set by the IAM login succeeding — NOT by the MPC exchange, which is a
// downstream call that may legitimately fail while the user is signed in.

const ACCESS_TOKEN_KEY = 'lux_mpc_access_token'
const REFRESH_TOKEN_KEY = 'lux_mpc_refresh_token'
const USER_EMAIL_KEY = 'lux_mpc_user_email'

export const SESSION_COOKIE = 'lux_mpc_session'

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
}

/**
 * Raise or clear the flag the middleware gates on.
 *
 * `Secure` is added only on https: an unconditional `Secure` meant the cookie
 * was silently dropped on http://localhost, so every local sign-in bounced
 * straight back to /login.
 */
export function markSession(on: boolean): void {
  if (typeof window === 'undefined') return
  const secure = window.location.protocol === 'https:' ? '; Secure' : ''
  document.cookie = on
    ? `${SESSION_COOKIE}=1; path=/; SameSite=Lax${secure}`
    : `${SESSION_COOKIE}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax${secure}`
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
  markSession(false)
}

export function isAuthenticated(): boolean {
  return getToken() !== null
}
