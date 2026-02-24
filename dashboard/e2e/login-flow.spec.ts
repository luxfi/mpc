import { test, expect } from '@playwright/test'

const IAM_URL = process.env.IAM_URL ?? 'https://lux.id'

/**
 * E2E tests for the full Lux ID → MPC Dashboard OAuth login flow.
 *
 * Tests verify:
 * 1. Unauthenticated users are redirected to /login
 * 2. Login page renders correctly with Lux branding
 * 3. OAuth implicit flow redirects to Lux ID
 * 4. Lux ID login form accepts credentials and redirects back
 * 5. MPC Dashboard receives the token and shows /dashboard
 *
 * Usage:
 *   TEST_PASSWORD='...' pnpm exec playwright test e2e/login-flow.spec.ts
 */

test.describe('Lux ID Login Flow', () => {
  test('unauthenticated root redirects to /login', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL(/\/login/)
  })

  test('login page shows Lux branding and Continue button', async ({ page }) => {
    await page.goto('/login')

    await expect(page.getByRole('heading')).toContainText(/Lux/)

    const continueBtn = page.getByRole('button', { name: /Continue with/i })
    await expect(continueBtn).toBeVisible()
    await expect(continueBtn).toContainText(/Lux ID/i)
  })

  test('Continue button redirects to Lux ID login page', async ({ page }) => {
    await page.goto('/login')

    const continueBtn = page.getByRole('button', { name: /Continue with/i })
    await continueBtn.click()

    await page.waitForURL(/lux\.id\/login/, { timeout: 15_000 })

    const url = new URL(page.url())
    expect(url.hostname).toBe('lux.id')
    expect(url.pathname).toBe('/login')
    expect(url.searchParams.get('response_type')).toBe('token')
    expect(url.searchParams.get('client_id')).toBe('lux-mpc')
    expect(url.searchParams.get('scope')).toContain('openid')
  })

  test('Lux ID login page loads with email and password fields', async ({ page }) => {
    const loginUrl = new URL(`${IAM_URL}/login`)
    loginUrl.searchParams.set('response_type', 'token')
    loginUrl.searchParams.set('client_id', 'lux-mpc')
    loginUrl.searchParams.set('redirect_uri', 'https://mpc.lux.network/auth/callback')
    loginUrl.searchParams.set('scope', 'openid profile email')
    loginUrl.searchParams.set('state', 'e2e-test')

    await page.goto(loginUrl.toString())

    // Email and Password fields
    const emailInput = page.getByPlaceholder('Email')
    const passwordInput = page.getByPlaceholder('Password')

    await expect(emailInput).toBeVisible({ timeout: 15_000 })
    await expect(passwordInput).toBeVisible()

    // Sign In button
    const signInBtn = page.getByRole('button', { name: /Sign In/i })
    await expect(signInBtn).toBeVisible()
  })

  test('full login flow with z@lux.network', async ({ page }) => {
    const password = process.env.TEST_PASSWORD
    test.skip(!password, 'TEST_PASSWORD env var required for login tests')

    await page.goto('/login')

    // Click continue to go to Lux ID
    await page.getByRole('button', { name: /Continue with/i }).click()

    // Wait for Lux ID login page
    await page.waitForURL(/lux\.id\/login/, { timeout: 15_000 })

    // Fill in credentials
    await page.getByPlaceholder('Email').fill('z@lux.network')
    await page.getByPlaceholder('Password').fill(password!)

    // Click Sign In
    await page.getByRole('button', { name: /Sign In/i }).click()

    // Should redirect back to MPC dashboard
    await page.waitForURL(/mpc\.lux\.network/, { timeout: 30_000 })

    // Wait for auth callback to process and redirect to dashboard
    if (page.url().includes('/auth/callback')) {
      await page.waitForURL(/\/dashboard/, { timeout: 15_000 })
    }

    await expect(page).toHaveURL(/\/dashboard/)
  })

  test('full login flow with a@lux.network', async ({ page }) => {
    const password = process.env.TEST_PASSWORD
    test.skip(!password, 'TEST_PASSWORD env var required for login tests')

    await page.goto('/login')
    await page.getByRole('button', { name: /Continue with/i }).click()

    await page.waitForURL(/lux\.id\/login/, { timeout: 15_000 })

    await page.getByPlaceholder('Email').fill('a@lux.network')
    await page.getByPlaceholder('Password').fill(password!)

    await page.getByRole('button', { name: /Sign In/i }).click()

    await page.waitForURL(/mpc\.lux\.network/, { timeout: 30_000 })

    if (page.url().includes('/auth/callback')) {
      await page.waitForURL(/\/dashboard/, { timeout: 15_000 })
    }

    await expect(page).toHaveURL(/\/dashboard/)
  })
})

test.describe('IAM OIDC Discovery', () => {
  test('OIDC discovery endpoint returns valid config', async ({ request }) => {
    // Use hanzo.id directly — lux.id sometimes returns login HTML on .well-known paths
    const response = await request.get('https://hanzo.id/.well-known/openid-configuration')
    expect(response.ok()).toBeTruthy()

    const config = await response.json()
    expect(config.issuer).toBeTruthy()
    expect(config.authorization_endpoint).toContain('/oauth/authorize')
    expect(config.token_endpoint).toContain('/oauth/token')
    expect(config.userinfo_endpoint).toContain('/oauth/userinfo')
    expect(config.jwks_uri).toContain('/.well-known/jwks')
    expect(config.response_types_supported).toContain('token')
  })

  test('JWKS endpoint returns valid keys', async ({ request }) => {
    // Use hanzo.id for JWKS since lux.id may proxy via login frontend
    const response = await request.get('https://hanzo.id/.well-known/jwks')
    expect(response.ok()).toBeTruthy()

    const jwks = await response.json()
    expect(jwks.keys).toBeDefined()
    expect(jwks.keys.length).toBeGreaterThan(0)
    expect(jwks.keys[0].kty).toBeTruthy()
  })

  test('app-lux-mpc application is accessible', async ({ request }) => {
    const response = await request.get('https://hanzo.id/api/get-application?id=admin/app-lux-mpc')
    expect(response.ok()).toBeTruthy()

    const body = await response.json()
    expect(body.data).toBeTruthy()
    expect(body.data.clientId).toBe('lux-mpc')
    expect(body.data.organization).toBe('lux')
  })
})

test.describe('MPC API Health', () => {
  test('healthz endpoint returns ok', async ({ request }) => {
    const baseUrl = process.env.BASE_URL ?? 'https://mpc.lux.network'
    const response = await request.get(`${baseUrl}/healthz`)
    expect(response.ok()).toBeTruthy()

    const body = await response.json()
    expect(body.status).toBe('ok')
  })
})
