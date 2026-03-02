// Package hsm provides password derivation from cloud HSM providers.
// This enables customer-owned encryption where an MPC node cannot start
// without the customer's cloud credentials — the ZapDB encryption password
// is stored as ciphertext that can only be decrypted via the customer's
// AWS KMS, GCP Cloud KMS, or Azure Key Vault.
package hsm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// PasswordProvider retrieves or derives a decrypted password string from
// an external secret store. Implementations must be safe for concurrent use.
type PasswordProvider interface {
	// GetPassword returns the plaintext password identified by keyID.
	// For cloud providers, keyID is typically a key ARN or alias.
	// The context should carry a deadline for network calls.
	GetPassword(ctx context.Context, keyID string) (string, error)
}

// ---------------------------------------------------------------------------
// 1. AWS KMS Provider
// ---------------------------------------------------------------------------

// AWSKMSProvider decrypts a ciphertext blob using the AWS KMS Decrypt API.
// The ciphertext is read from the ZAPDB_ENCRYPTED_PASSWORD env var (base64).
// Authentication uses the standard AWS credential chain:
//
//	AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional).
//
// If running on EC2/ECS/Lambda, the instance role is used automatically
// via the instance metadata service.
type AWSKMSProvider struct {
	KeyID  string // KMS key ARN or alias
	Region string // AWS region (e.g. us-east-1)
}

// GetPassword decrypts the ZAPDB_ENCRYPTED_PASSWORD ciphertext via AWS KMS.
func (p *AWSKMSProvider) GetPassword(ctx context.Context, keyID string) (string, error) {
	if keyID != "" {
		p.KeyID = keyID
	}

	region := p.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	ciphertextB64 := os.Getenv("ZAPDB_ENCRYPTED_PASSWORD")
	if ciphertextB64 == "" {
		return "", fmt.Errorf("hsm/aws: ZAPDB_ENCRYPTED_PASSWORD env var is empty")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("hsm/aws: failed to base64-decode ciphertext: %w", err)
	}

	// Build request body for KMS Decrypt
	reqBody := map[string]interface{}{
		"CiphertextBlob": base64.StdEncoding.EncodeToString(ciphertext),
	}
	if p.KeyID != "" {
		reqBody["KeyId"] = p.KeyID
	}
	bodyJSON, _ := json.Marshal(reqBody)

	endpoint := fmt.Sprintf("https://kms.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", fmt.Errorf("hsm/aws: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Decrypt")

	// Sign the request with AWS Signature V4
	if err := signAWSRequest(req, bodyJSON, region, "kms"); err != nil {
		return "", fmt.Errorf("hsm/aws: failed to sign request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hsm/aws: KMS request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hsm/aws: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Plaintext string `json:"Plaintext"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("hsm/aws: failed to parse KMS response: %w", err)
	}
	if result.Plaintext == "" {
		return "", fmt.Errorf("hsm/aws: KMS returned empty plaintext")
	}

	plaintext, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil {
		return "", fmt.Errorf("hsm/aws: failed to decode plaintext: %w", err)
	}

	return string(plaintext), nil
}

// signAWSRequest signs an HTTP request using AWS Signature V4.
// Uses credentials from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars,
// or from the EC2 instance metadata service if env vars are not set.
func signAWSRequest(req *http.Request, body []byte, region, service string) error {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	// If no static creds, try EC2 instance metadata (IMDSv2)
	if accessKey == "" || secretKey == "" {
		creds, err := getEC2RoleCredentials()
		if err != nil {
			return fmt.Errorf("no AWS credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or use an EC2 instance role: %w", err)
		}
		accessKey = creds.accessKeyID
		secretKey = creds.secretAccessKey
		sessionToken = creds.sessionToken
	}

	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	// Canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := ""

	// Signed headers (sorted)
	signedHeaderKeys := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if sessionToken != "" {
		signedHeaderKeys = append(signedHeaderKeys, "x-amz-security-token")
	}
	sort.Strings(signedHeaderKeys)
	signedHeaders := strings.Join(signedHeaderKeys, ";")

	var canonicalHeaders strings.Builder
	for _, h := range signedHeaderKeys {
		var val string
		switch h {
		case "host":
			val = req.URL.Host
		default:
			val = req.Header.Get(h)
		}
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(val))
		canonicalHeaders.WriteString("\n")
	}

	payloadHash := sha256Hex(body)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	// String to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Signing key
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authHeader)

	return nil
}

type ec2Creds struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

// getEC2RoleCredentials fetches temporary credentials from the EC2 instance
// metadata service (IMDSv2).
func getEC2RoleCredentials() (*ec2Creds, error) {
	client := &http.Client{Timeout: 2 * time.Second}

	// Step 1: Get IMDSv2 token
	tokenReq, _ := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("IMDS token request failed: %w", err)
	}
	defer tokenResp.Body.Close()
	tokenBytes, _ := io.ReadAll(tokenResp.Body)
	token := strings.TrimSpace(string(tokenBytes))

	// Step 2: Get role name
	roleReq, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	roleReq.Header.Set("X-aws-ec2-metadata-token", token)
	roleResp, err := client.Do(roleReq)
	if err != nil {
		return nil, fmt.Errorf("IMDS role request failed: %w", err)
	}
	defer roleResp.Body.Close()
	roleBytes, _ := io.ReadAll(roleResp.Body)
	roleName := strings.TrimSpace(string(roleBytes))
	if roleName == "" {
		return nil, fmt.Errorf("no IAM role attached to instance")
	}

	// Step 3: Get credentials
	credReq, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/iam/security-credentials/"+roleName, nil)
	credReq.Header.Set("X-aws-ec2-metadata-token", token)
	credResp, err := client.Do(credReq)
	if err != nil {
		return nil, fmt.Errorf("IMDS credential request failed: %w", err)
	}
	defer credResp.Body.Close()
	credBytes, _ := io.ReadAll(credResp.Body)

	var result struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.Unmarshal(credBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse IMDS credentials: %w", err)
	}

	return &ec2Creds{
		accessKeyID:     result.AccessKeyId,
		secretAccessKey: result.SecretAccessKey,
		sessionToken:    result.Token,
	}, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// 2. GCP Cloud KMS Provider
// ---------------------------------------------------------------------------

// GCPKMSProvider decrypts a ciphertext blob using the GCP Cloud KMS REST API.
// Authentication uses the GCE metadata server to obtain an OAuth2 access token
// (works on GCE, GKE, Cloud Run). For local development, set
// GOOGLE_APPLICATION_CREDENTIALS to a service account key file and this
// provider will use it.
type GCPKMSProvider struct {
	ProjectID   string // GCP project ID
	LocationID  string // KMS location (e.g. "global", "us-east1")
	KeyRingID   string // KMS key ring name
	CryptoKeyID string // KMS crypto key name
}

// GetPassword decrypts the ZAPDB_ENCRYPTED_PASSWORD ciphertext via GCP Cloud KMS.
func (p *GCPKMSProvider) GetPassword(ctx context.Context, keyID string) (string, error) {
	// If keyID is a full resource name, parse it
	if keyID != "" && strings.Contains(keyID, "/") {
		parts := parseGCPKeyResourceName(keyID)
		if parts != nil {
			p.ProjectID = parts["project"]
			p.LocationID = parts["location"]
			p.KeyRingID = parts["keyRing"]
			p.CryptoKeyID = parts["cryptoKey"]
		}
	}

	if p.ProjectID == "" {
		p.ProjectID = os.Getenv("GCP_PROJECT_ID")
	}
	if p.LocationID == "" {
		p.LocationID = os.Getenv("GCP_KMS_LOCATION")
		if p.LocationID == "" {
			p.LocationID = "global"
		}
	}
	if p.KeyRingID == "" {
		p.KeyRingID = os.Getenv("GCP_KMS_KEYRING")
	}
	if p.CryptoKeyID == "" {
		p.CryptoKeyID = os.Getenv("GCP_KMS_KEY")
	}

	if p.ProjectID == "" || p.KeyRingID == "" || p.CryptoKeyID == "" {
		return "", fmt.Errorf("hsm/gcp: ProjectID, KeyRingID, and CryptoKeyID are required")
	}

	ciphertextB64 := os.Getenv("ZAPDB_ENCRYPTED_PASSWORD")
	if ciphertextB64 == "" {
		return "", fmt.Errorf("hsm/gcp: ZAPDB_ENCRYPTED_PASSWORD env var is empty")
	}

	// Get OAuth2 token from GCE metadata service
	accessToken, err := getGCPAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to get access token: %w", err)
	}

	// Build KMS decrypt request
	endpoint := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s:decrypt",
		url.PathEscape(p.ProjectID),
		url.PathEscape(p.LocationID),
		url.PathEscape(p.KeyRingID),
		url.PathEscape(p.CryptoKeyID),
	)

	reqBody, _ := json.Marshal(map[string]string{
		"ciphertext": ciphertextB64,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: KMS request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hsm/gcp: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to parse KMS response: %w", err)
	}
	if result.Plaintext == "" {
		return "", fmt.Errorf("hsm/gcp: KMS returned empty plaintext")
	}

	plaintext, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil {
		return "", fmt.Errorf("hsm/gcp: failed to decode plaintext: %w", err)
	}

	return string(plaintext), nil
}

// getGCPAccessToken retrieves an OAuth2 access token from the GCE metadata server.
func getGCPAccessToken(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata request failed (not running on GCE/GKE?): %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token from metadata")
	}

	return tokenResp.AccessToken, nil
}

// parseGCPKeyResourceName parses a full GCP KMS key resource name.
// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}
func parseGCPKeyResourceName(name string) map[string]string {
	parts := strings.Split(name, "/")
	if len(parts) < 8 {
		return nil
	}
	result := make(map[string]string)
	for i := 0; i < len(parts)-1; i += 2 {
		key := parts[i]
		val := parts[i+1]
		switch key {
		case "projects":
			result["project"] = val
		case "locations":
			result["location"] = val
		case "keyRings":
			result["keyRing"] = val
		case "cryptoKeys":
			result["cryptoKey"] = val
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// 3. Azure Key Vault Provider
// ---------------------------------------------------------------------------

// AzureKVProvider decrypts or unwraps a key using Azure Key Vault.
// Authentication uses Managed Service Identity (MSI) to obtain an access
// token — works on Azure VMs, AKS, Container Apps, and App Service.
type AzureKVProvider struct {
	VaultURL   string // e.g. "https://my-vault.vault.azure.net"
	KeyName    string // Key name in the vault
	KeyVersion string // Key version (empty = latest)
}

// GetPassword unwraps the ZAPDB_ENCRYPTED_PASSWORD ciphertext via Azure Key Vault.
func (p *AzureKVProvider) GetPassword(ctx context.Context, keyID string) (string, error) {
	if keyID != "" {
		// keyID can be "vault/key/version" or just "key"
		parts := strings.Split(keyID, "/")
		switch len(parts) {
		case 3:
			p.VaultURL = parts[0]
			p.KeyName = parts[1]
			p.KeyVersion = parts[2]
		case 2:
			p.KeyName = parts[0]
			p.KeyVersion = parts[1]
		case 1:
			p.KeyName = parts[0]
		}
	}

	if p.VaultURL == "" {
		p.VaultURL = os.Getenv("AZURE_VAULT_URL")
	}
	if p.KeyName == "" {
		p.KeyName = os.Getenv("AZURE_KEY_NAME")
	}
	if p.KeyVersion == "" {
		p.KeyVersion = os.Getenv("AZURE_KEY_VERSION")
	}

	if p.VaultURL == "" || p.KeyName == "" {
		return "", fmt.Errorf("hsm/azure: VaultURL and KeyName are required")
	}

	ciphertextB64 := os.Getenv("ZAPDB_ENCRYPTED_PASSWORD")
	if ciphertextB64 == "" {
		return "", fmt.Errorf("hsm/azure: ZAPDB_ENCRYPTED_PASSWORD env var is empty")
	}

	// Get access token from Azure MSI
	accessToken, err := getAzureMSIToken(ctx)
	if err != nil {
		return "", fmt.Errorf("hsm/azure: failed to get MSI token: %w", err)
	}

	// Build the unwrapKey request
	vaultURL := strings.TrimRight(p.VaultURL, "/")
	keyPath := fmt.Sprintf("%s/keys/%s", vaultURL, p.KeyName)
	if p.KeyVersion != "" {
		keyPath += "/" + p.KeyVersion
	}
	endpoint := keyPath + "/unwrapkey?api-version=7.4"

	reqBody, _ := json.Marshal(map[string]string{
		"alg":   "RSA-OAEP-256",
		"value": ciphertextB64,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("hsm/azure: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hsm/azure: Key Vault request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hsm/azure: Key Vault returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("hsm/azure: failed to parse Key Vault response: %w", err)
	}
	if result.Value == "" {
		return "", fmt.Errorf("hsm/azure: Key Vault returned empty value")
	}

	// Azure returns base64url-encoded result
	plaintext, err := base64.RawURLEncoding.DecodeString(result.Value)
	if err != nil {
		return "", fmt.Errorf("hsm/azure: failed to decode plaintext: %w", err)
	}

	return string(plaintext), nil
}

// getAzureMSIToken retrieves an access token using Managed Service Identity.
func getAzureMSIToken(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	msiEndpoint := os.Getenv("IDENTITY_ENDPOINT")
	msiHeader := os.Getenv("IDENTITY_HEADER")

	var tokenURL string
	var req *http.Request

	if msiEndpoint != "" {
		// App Service / Container Apps style
		tokenURL = fmt.Sprintf("%s?api-version=2019-08-01&resource=https://vault.azure.net", msiEndpoint)
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
		req.Header.Set("X-IDENTITY-HEADER", msiHeader)
	} else {
		// VM / VMSS style (IMDS)
		tokenURL = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
		req.Header.Set("Metadata", "true")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("MSI token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MSI returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse MSI token: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token from MSI")
	}

	return tokenResp.AccessToken, nil
}

// ---------------------------------------------------------------------------
// 4. Env Provider (development / local)
// ---------------------------------------------------------------------------

// EnvProvider reads a password directly from an environment variable.
// This is suitable for development and local testing. In production,
// use one of the cloud KMS providers instead.
type EnvProvider struct {
	EnvVar string // defaults to "LUX_MPC_PASSWORD"
}

// GetPassword reads the password from the configured env var.
func (p *EnvProvider) GetPassword(_ context.Context, _ string) (string, error) {
	envVar := p.EnvVar
	if envVar == "" {
		envVar = "LUX_MPC_PASSWORD"
	}

	password := os.Getenv(envVar)
	if password == "" {
		// Try legacy config key
		password = os.Getenv("ZAPDB_PASSWORD")
	}
	if password == "" {
		return "", fmt.Errorf("hsm/env: environment variable %s is not set", envVar)
	}

	return password, nil
}

// ---------------------------------------------------------------------------
// 5. File Provider
// ---------------------------------------------------------------------------

// FileProvider reads a password from a file on disk. This is useful for
// Kubernetes secrets mounted as volumes, Docker secrets, or any system
// where the password is provisioned as a file.
type FileProvider struct {
	Path string // path to password file
}

// GetPassword reads the password from the configured file path.
func (p *FileProvider) GetPassword(_ context.Context, keyID string) (string, error) {
	path := p.Path
	if path == "" && keyID != "" {
		path = keyID
	}
	if path == "" {
		path = os.Getenv("MPC_PASSWORD_FILE")
	}
	if path == "" {
		return "", fmt.Errorf("hsm/file: no file path configured (set Path, keyID, or MPC_PASSWORD_FILE)")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hsm/file: failed to read password file %s: %w", path, err)
	}

	password := strings.TrimRight(string(data), "\n\r")
	if password == "" {
		return "", fmt.Errorf("hsm/file: password file %s is empty", path)
	}

	return password, nil
}
