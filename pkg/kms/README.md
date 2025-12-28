# MPC Key Management with KMS

This package provides secure key management for MPC nodes using KMS, a secrets management platform.

## Overview

The KMS integration allows MPC nodes to:
- Store MPC key shares securely in KMS instead of local BadgerDB
- Retrieve key shares on demand with proper authentication
- Manage initiator keys and other sensitive data
- Maintain encrypted backups of non-sensitive data locally

## Configuration

Add the following to your `config.yaml`:

```yaml
kms:
  # For local KMS instance
  site_url: "http://localhost:8080"
  
  # For production KMS
  # site_url: "https://kms.lux.network"
  
  # Required settings
  project_id: "your-project-id"
  environment: "prod"
  secret_path: "/mpc"
  
  # Authentication (choose one method)
  # Method 1: Service Token
  # Set KMS_TOKEN environment variable
  
  # Method 2: Universal Auth (recommended)
  client_id: "your-client-id"
  client_secret: "your-client-secret"
```

## Setup

1. **Local KMS** (if using):
   ```bash
   cd ~/work/lux/kms
   docker-compose -f docker-compose.dev.yml up -d
   ```

2. **Create a Project** in KMS:
   - Log in to KMS dashboard
   - Create a new project for MPC
   - Note the project ID

3. **Set up Authentication**:
   
   **Option A: Service Token (Quick Start)**
   ```bash
   # In KMS dashboard, create a service token
   export KMS_TOKEN="st.your-service-token"
   export KMS_PROJECT_ID="your-project-id"
   ```
   
   **Option B: Universal Auth (Production)**
   - Create a machine identity in KMS
   - Get the client ID and client secret
   - Add to config.yaml

## Usage

The integration automatically activates when KMS is configured. MPC nodes will:

1. Store new key shares in KMS
2. Keep only references in local BadgerDB
3. Retrieve keys from KMS when needed
4. Fall back to local storage if KMS is unavailable

## Testing

Run the test script to verify your setup:

```bash
cd /Users/z/work/lux/mpc/scripts
go run test-kms.go
```

## Security Notes

- Never commit KMS credentials to git
- Use environment variables or secure config management
- Enable audit logging in KMS for compliance
- Regularly rotate service tokens
- Use Universal Auth with proper RBAC in production

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│  MPC Node   │────▶│ KMS Wrapper  │────▶│  KMS   │
│             │     │              │     │            │
│  BadgerDB   │◀────│  (References)│     │ (Secrets)  │
└─────────────┘     └──────────────┘     └────────────┘
```

- MPC nodes use the KMS-enabled kvstore wrapper
- Sensitive keys are stored in KMS
- Local BadgerDB stores only references
- Non-sensitive data remains in BadgerDB

## Troubleshooting

1. **Connection Failed**: Check KMS URL and network connectivity
2. **Auth Failed**: Verify credentials and project access
3. **Key Not Found**: Ensure correct environment and secret path
4. **Fallback Active**: Check logs for KMS errors

## Benefits

- **Central Key Management**: All MPC keys in one secure location
- **Access Control**: Fine-grained permissions per node
- **Audit Trail**: Complete history of key access
- **Key Rotation**: Simplified key rotation procedures
- **Compliance**: Meet security standards with proper KMS