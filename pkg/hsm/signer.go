// Package hsm signing extension.
//
// While PasswordProvider handles symmetric decryption of ZapDB passwords,
// Signer provides asymmetric signing/verification for intent co-signing,
// settlement attestation, and other operations requiring HSM-backed keys.
//
// Supported providers:
//   - AWS KMS (ECDSA_SHA_256, RSA_PKCS1_SHA_256)
//   - GCP Cloud KMS (EC_SIGN_P256_SHA256, RSA_SIGN_PKCS1_2048_SHA256)
//   - Zymbit SCM (ECDSA P-256 via local PKCS#11)
//   - Local (Ed25519/ECDSA for development — NOT FOR PRODUCTION)
package hsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Signer provides asymmetric signing and verification using HSM-backed keys.
// This is used for intent co-signing (server-side HSM) and settlement attestation.
type Signer interface {
	// Sign produces a signature over the given message using the HSM key.
	Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)

	// Verify checks a signature against the given message using the HSM key.
	Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error)

	// Provider returns the provider name (e.g., "aws", "gcp", "zymbit", "local").
	Provider() string
}

// NewSigner creates a Signer for the given provider type.
// Supported: "aws", "gcp", "zymbit", "local".
func NewSigner(providerType string, config map[string]string) (Signer, error) {
	providerType = strings.TrimSpace(strings.ToLower(providerType))
	switch providerType {
	case "aws":
		region := ""
		if config != nil {
			region = config["region"]
		}
		return &AWSKMSSigner{Region: region}, nil
	case "gcp":
		return &GCPKMSSigner{}, nil
	case "zymbit":
		return &ZymbitSigner{}, nil
	case "local", "":
		return NewLocalSigner()
	default:
		return nil, fmt.Errorf("hsm: unknown signer provider %q (supported: aws, gcp, zymbit, local)", providerType)
	}
}

// ---------------------------------------------------------------------------
// AWS KMS Signer
// ---------------------------------------------------------------------------

// AWSKMSSigner signs messages using AWS KMS asymmetric keys.
// KeyID should be a KMS key ARN or alias configured for SIGN_VERIFY usage.
type AWSKMSSigner struct {
	Region string
}

func (s *AWSKMSSigner) Provider() string { return "aws" }

func (s *AWSKMSSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	region := s.Region
	if region == "" {
		region = "us-east-1"
	}

	// Hash the message (AWS KMS expects a digest for ECDSA_SHA_256)
	digest := sha256.Sum256(message)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"KeyId":            keyID,
		"Message":          base64.StdEncoding.EncodeToString(digest[:]),
		"MessageType":      "DIGEST",
		"SigningAlgorithm": "ECDSA_SHA_256",
	})

	endpoint := fmt.Sprintf("https://kms.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Sign")

	if err := signAWSRequest(req, reqBody, region, "kms"); err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to sign request: %w", err)
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm/aws-sign: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Signature string `json:"Signature"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to parse response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("hsm/aws-sign: failed to decode signature: %w", err)
	}

	return sig, nil
}

func (s *AWSKMSSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	region := s.Region
	if region == "" {
		region = "us-east-1"
	}

	digest := sha256.Sum256(message)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"KeyId":            keyID,
		"Message":          base64.StdEncoding.EncodeToString(digest[:]),
		"MessageType":      "DIGEST",
		"Signature":        base64.StdEncoding.EncodeToString(signature),
		"SigningAlgorithm": "ECDSA_SHA_256",
	})

	endpoint := fmt.Sprintf("https://kms.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return false, fmt.Errorf("hsm/aws-verify: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Verify")

	if err := signAWSRequest(req, reqBody, region, "kms"); err != nil {
		return false, fmt.Errorf("hsm/aws-verify: failed to sign request: %w", err)
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("hsm/aws-verify: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hsm/aws-verify: KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		SignatureValid bool `json:"SignatureValid"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, fmt.Errorf("hsm/aws-verify: failed to parse response: %w", err)
	}

	return result.SignatureValid, nil
}

// ---------------------------------------------------------------------------
// GCP Cloud KMS Signer
// ---------------------------------------------------------------------------

// GCPKMSSigner signs messages using Google Cloud KMS asymmetric keys.
// KeyID should be the full resource name:
//
//	projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
type GCPKMSSigner struct{}

func (s *GCPKMSSigner) Provider() string { return "gcp" }

func (s *GCPKMSSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	accessToken, err := getGCPAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to get access token: %w", err)
	}

	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"digest": map[string]string{
			"sha256": base64.StdEncoding.EncodeToString(digest[:]),
		},
	})

	endpoint := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/%s:asymmetricSign",
		url.PathEscape(keyID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm/gcp-sign: Cloud KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to parse response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp-sign: failed to decode signature: %w", err)
	}

	return sig, nil
}

func (s *GCPKMSSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	// GCP Cloud KMS doesn't have a Verify API for asymmetric signing —
	// verification must be done locally using the public key.
	accessToken, err := getGCPAccessToken(ctx)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to get access token: %w", err)
	}

	// Get the public key
	endpoint := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/%s:getPublicKey",
		url.PathEscape(keyID),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hsm/gcp-verify: Cloud KMS returned %d: %s", resp.StatusCode, string(respBody))
	}

	var pubKeyResp struct {
		Pem string `json:"pem"`
	}
	if err := json.Unmarshal(respBody, &pubKeyResp); err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to parse public key: %w", err)
	}

	// Parse PEM public key
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to decode PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("hsm/gcp-verify: failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("hsm/gcp-verify: public key is not ECDSA")
	}

	// Verify the signature
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(ecdsaPub, digest[:], signature), nil
}

// ---------------------------------------------------------------------------
// Zymbit Signer
// ---------------------------------------------------------------------------

// ZymbitSigner signs messages using a local Zymbit SCM device.
// KeyID is the slot number (e.g., "0", "1").
// Note: This implementation uses the Zymbit REST API at localhost:6789
// which requires the zymbit-api service running on the device.
type ZymbitSigner struct {
	APIAddr string // defaults to "http://localhost:6789"
}

func (s *ZymbitSigner) Provider() string { return "zymbit" }

func (s *ZymbitSigner) apiAddr() string {
	if s.APIAddr != "" {
		return s.APIAddr
	}
	return "http://localhost:6789"
}

func (s *ZymbitSigner) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"slot":   keyID,
		"digest": base64.StdEncoding.EncodeToString(digest[:]),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiAddr()+"/sign", strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm/zymbit-sign: returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: failed to parse response: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit-sign: failed to decode signature: %w", err)
	}

	return sig, nil
}

func (s *ZymbitSigner) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	digest := sha256.Sum256(message)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"slot":      keyID,
		"digest":    base64.StdEncoding.EncodeToString(digest[:]),
		"signature": base64.StdEncoding.EncodeToString(signature),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiAddr()+"/verify", strings.NewReader(string(reqBody)))
	if err != nil {
		return false, fmt.Errorf("hsm/zymbit-verify: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("hsm/zymbit-verify: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hsm/zymbit-verify: returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, fmt.Errorf("hsm/zymbit-verify: failed to parse response: %w", err)
	}

	return result.Valid, nil
}

// ---------------------------------------------------------------------------
// Local Signer (development only)
// ---------------------------------------------------------------------------

// LocalSigner uses a local ECDSA P-256 key for development/testing.
// NOT FOR PRODUCTION — the key exists only in memory.
type LocalSigner struct {
	keys map[string]*ecdsa.PrivateKey
}

func NewLocalSigner() (*LocalSigner, error) {
	return &LocalSigner{keys: make(map[string]*ecdsa.PrivateKey)}, nil
}

func (s *LocalSigner) Provider() string { return "local" }

func (s *LocalSigner) getOrCreateKey(keyID string) (*ecdsa.PrivateKey, error) {
	if k, ok := s.keys[keyID]; ok {
		return k, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s.keys[keyID] = k
	return k, nil
}

func (s *LocalSigner) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	key, err := s.getOrCreateKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("hsm/local: failed to get key: %w", err)
	}
	digest := sha256.Sum256(message)
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("hsm/local: signing failed: %w", err)
	}
	// DER encode the signature
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, sv})
	if err != nil {
		return nil, fmt.Errorf("hsm/local: failed to encode signature: %w", err)
	}
	return sig, nil
}

func (s *LocalSigner) Verify(_ context.Context, keyID string, message, signature []byte) (bool, error) {
	key, err := s.getOrCreateKey(keyID)
	if err != nil {
		return false, fmt.Errorf("hsm/local: failed to get key: %w", err)
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature), nil
}
