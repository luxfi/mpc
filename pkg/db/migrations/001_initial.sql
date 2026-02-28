-- MPC Dashboard Schema
-- Organizations (top-level tenant)
CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer',
  mfa_secret TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- API Keys (per-org, for programmatic access)
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  permissions TEXT[] DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);

-- Vaults (logical grouping of wallets)
CREATE TABLE IF NOT EXISTS vaults (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  app_id TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Wallets (MPC-generated keys)
CREATE TABLE IF NOT EXISTS wallets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id UUID REFERENCES vaults(id) ON DELETE CASCADE,
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  wallet_id TEXT UNIQUE NOT NULL,
  name TEXT,
  key_type TEXT NOT NULL,
  ecdsa_pubkey TEXT,
  eddsa_pubkey TEXT,
  eth_address TEXT,
  btc_address TEXT,
  sol_address TEXT,
  threshold INT NOT NULL,
  participants TEXT[] NOT NULL,
  version INT DEFAULT 1,
  status TEXT DEFAULT 'active',
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Transactions
CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  wallet_id UUID REFERENCES wallets(id) ON DELETE SET NULL,
  tx_type TEXT NOT NULL,
  chain TEXT NOT NULL,
  to_address TEXT,
  amount TEXT,
  token TEXT,
  tx_hash TEXT,
  raw_tx BYTEA,
  signature_r TEXT,
  signature_s TEXT,
  signature_eddsa TEXT,
  status TEXT DEFAULT 'pending',
  initiated_by UUID REFERENCES users(id),
  approved_by UUID[],
  rejected_by UUID,
  rejection_reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  signed_at TIMESTAMPTZ,
  broadcast_at TIMESTAMPTZ
);

-- Policy Rules
CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  vault_id UUID REFERENCES vaults(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  priority INT DEFAULT 0,
  action TEXT NOT NULL,
  conditions JSONB NOT NULL,
  required_approvers INT DEFAULT 1,
  approver_roles TEXT[] DEFAULT '{admin}',
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Whitelisted Addresses
CREATE TABLE IF NOT EXISTS address_whitelist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  vault_id UUID REFERENCES vaults(id) ON DELETE SET NULL,
  address TEXT NOT NULL,
  chain TEXT NOT NULL,
  label TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  details JSONB,
  ip_address TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Webhooks
CREATE TABLE IF NOT EXISTS webhooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT[] NOT NULL,
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Subscriptions (recurring payments)
CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  wallet_id UUID REFERENCES wallets(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  provider_name TEXT,
  recipient_address TEXT NOT NULL,
  chain TEXT NOT NULL,
  token TEXT,
  amount TEXT NOT NULL,
  currency TEXT DEFAULT 'USD',
  interval TEXT NOT NULL,
  next_payment_at TIMESTAMPTZ NOT NULL,
  last_payment_at TIMESTAMPTZ,
  last_tx_id UUID REFERENCES transactions(id) ON DELETE SET NULL,
  status TEXT DEFAULT 'active',
  max_retries INT DEFAULT 3,
  retry_count INT DEFAULT 0,
  require_balance BOOLEAN DEFAULT true,
  created_by UUID REFERENCES users(id),
  cancelled_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  cancelled_at TIMESTAMPTZ
);

-- Payment Requests (inbound)
CREATE TABLE IF NOT EXISTS payment_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  wallet_id UUID REFERENCES wallets(id) ON DELETE SET NULL,
  request_token TEXT UNIQUE NOT NULL,
  merchant_name TEXT,
  recipient_address TEXT NOT NULL,
  chain TEXT NOT NULL,
  token TEXT,
  amount TEXT NOT NULL,
  memo TEXT,
  status TEXT DEFAULT 'pending',
  expires_at TIMESTAMPTZ,
  paid_tx_id UUID REFERENCES transactions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Smart Contract Wallets (Safe/ERC-4337)
CREATE TABLE IF NOT EXISTS smart_wallets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_id UUID REFERENCES wallets(id) ON DELETE CASCADE,
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  chain TEXT NOT NULL,
  contract_address TEXT NOT NULL,
  wallet_type TEXT NOT NULL,
  factory_address TEXT,
  entrypoint_address TEXT,
  salt TEXT,
  owners TEXT[] NOT NULL,
  threshold INT NOT NULL,
  status TEXT DEFAULT 'active',
  deployed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_vaults_org ON vaults(org_id);
CREATE INDEX IF NOT EXISTS idx_wallets_vault ON wallets(vault_id);
CREATE INDEX IF NOT EXISTS idx_wallets_org ON wallets(org_id);
CREATE INDEX IF NOT EXISTS idx_wallets_wallet_id ON wallets(wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_org ON transactions(org_id);
CREATE INDEX IF NOT EXISTS idx_transactions_wallet ON transactions(wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_policies_org ON policies(org_id);
CREATE INDEX IF NOT EXISTS idx_policies_vault ON policies(vault_id);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_org ON subscriptions(org_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_next ON subscriptions(next_payment_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_payment_requests_token ON payment_requests(request_token);
CREATE INDEX IF NOT EXISTS idx_smart_wallets_wallet ON smart_wallets(wallet_id);
