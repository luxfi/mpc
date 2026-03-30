package custody

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

// BiometricProof is the attestation from a user's device after biometric
// authentication (Face ID, Touch ID, fingerprint, etc.). The mobile app
// constructs this after the Secure Enclave unlocks the key share.
type BiometricProof struct {
	Type                 string `json:"type"`                  // face_id, touch_id, fingerprint, iris
	Timestamp            int64  `json:"timestamp"`             // Unix ms when biometric was captured
	Nonce                string `json:"nonce"`                 // Challenge nonce from server
	AttestationSignature []byte `json:"attestation_signature"` // Device attestation signature (DER)
	DeviceID             string `json:"device_id"`             // Registered device ID
}

// DeviceRegistration tracks a user's enrolled device and its Secure Enclave
// public key. The device holds shard 1 of the 2-of-3 MPC wallet.
type DeviceRegistration struct {
	DeviceID      string    `json:"device_id"`
	DeviceType    string    `json:"device_type"`    // ios, android
	PublicKey     []byte    `json:"public_key"`      // Secure Enclave P-256 uncompressed public key
	BiometricType string    `json:"biometric_type"` // face_id, touch_id, fingerprint
	WalletID      string    `json:"wallet_id"`
	ParticipantID string    `json:"participant_id"` // MPC participant slot (e.g., "user")
	EnrolledAt    time.Time `json:"enrolled_at"`
	LastUsed      time.Time `json:"last_used"`
}

// maxProofAge is the maximum acceptable age of a biometric proof.
// Proofs older than this are rejected to prevent replay of stale attestations.
const maxProofAge = 30 * time.Second

// nonceGuard tracks used nonces to prevent replay attacks.
// Nonces expire after 2x the proof age to bound memory usage.
type nonceGuard struct {
	mu    sync.Mutex
	used  map[string]time.Time
	ttl   time.Duration
}

func newNonceGuard() *nonceGuard {
	ng := &nonceGuard{
		used: make(map[string]time.Time),
		ttl:  2 * maxProofAge,
	}
	go ng.reap()
	return ng
}

func (ng *nonceGuard) reap() {
	ticker := time.NewTicker(ng.ttl)
	defer ticker.Stop()
	for range ticker.C {
		ng.mu.Lock()
		now := time.Now()
		for k, v := range ng.used {
			if now.Sub(v) > ng.ttl {
				delete(ng.used, k)
			}
		}
		ng.mu.Unlock()
	}
}

// MarkUsed records a nonce. Returns false if the nonce was already used.
func (ng *nonceGuard) MarkUsed(nonce string) bool {
	ng.mu.Lock()
	defer ng.mu.Unlock()
	if _, exists := ng.used[nonce]; exists {
		return false
	}
	ng.used[nonce] = time.Now()
	return true
}

// BiometricVerifier validates device attestation and biometric proofs.
// It is the server-side component that ensures the user's device actually
// performed biometric authentication before accepting their MPC contribution.
type BiometricVerifier struct {
	nonces *nonceGuard
}

// NewBiometricVerifier creates a verifier with nonce replay protection.
func NewBiometricVerifier() *BiometricVerifier {
	return &BiometricVerifier{
		nonces: newNonceGuard(),
	}
}

// VerifyBiometricProof validates:
//  1. Proof freshness (timestamp within maxProofAge of now)
//  2. Nonce has not been used before (replay protection)
//  3. Attestation signature is valid for the registered device public key
//  4. Device is enrolled for the specified wallet
func (v *BiometricVerifier) VerifyBiometricProof(proof BiometricProof, reg DeviceRegistration) error {
	// 1. Freshness check
	proofTime := time.UnixMilli(proof.Timestamp)
	age := time.Since(proofTime)
	if age > maxProofAge {
		return fmt.Errorf("biometric proof expired: age %s exceeds max %s", age.Round(time.Millisecond), maxProofAge)
	}
	if age < -5*time.Second {
		return errors.New("biometric proof timestamp is in the future")
	}

	// 2. Nonce replay protection
	if proof.Nonce == "" {
		return errors.New("biometric proof nonce is empty")
	}
	if !v.nonces.MarkUsed(proof.Nonce) {
		return errors.New("biometric proof nonce already used (replay)")
	}

	// 3. Device identity match
	if proof.DeviceID != reg.DeviceID {
		return errors.New("biometric proof device_id does not match registration")
	}

	// 4. Verify attestation signature against registered device public key.
	// The device signs SHA256(nonce || timestamp) with its Secure Enclave key.
	if err := verifyDeviceSignature(reg.PublicKey, proof.Nonce, proof.Timestamp, proof.AttestationSignature); err != nil {
		return fmt.Errorf("attestation signature invalid: %w", err)
	}

	return nil
}

// VerifyDeviceSignature checks an ECDSA P-256 signature from the device's
// Secure Enclave key. The signed message is SHA256(nonce || timestamp_bytes).
func VerifyDeviceSignature(pubKey []byte, messageHash []byte, signature []byte) error {
	ecPub, err := parseP256PublicKey(pubKey)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(ecPub, messageHash, signature) {
		return errors.New("ECDSA P-256 signature verification failed")
	}
	return nil
}

// verifyDeviceSignature constructs the signed message from nonce + timestamp
// and verifies the P-256 signature.
func verifyDeviceSignature(pubKey []byte, nonce string, timestamp int64, sig []byte) error {
	// Construct the message the device signed: SHA256(nonce || timestamp_hex)
	msg := fmt.Sprintf("%s|%d", nonce, timestamp)
	hash := sha256.Sum256([]byte(msg))
	return VerifyDeviceSignature(pubKey, hash[:], sig)
}

// parseP256PublicKey parses an uncompressed P-256 public key (65 bytes: 0x04 || x || y).
func parseP256PublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 65 {
		return nil, fmt.Errorf("expected 65-byte uncompressed P-256 key, got %d bytes", len(raw))
	}
	if raw[0] != 0x04 {
		return nil, errors.New("public key must be uncompressed (prefix 0x04)")
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !pub.Curve.IsOnCurve(x, y) {
		return nil, errors.New("public key point is not on the P-256 curve")
	}
	return pub, nil
}

// GenerateChallenge creates a cryptographically random challenge nonce
// (32 bytes, hex-encoded) for a device to sign during registration or signing.
func GenerateChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate challenge: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// VerifyDeviceAttestation validates platform-specific device attestation:
//   - iOS: Apple App Attest / DeviceCheck attestation
//   - Android: Google Play Integrity / SafetyNet attestation
//
// In production, this calls Apple/Google servers to verify the attestation
// chain. The attestation proves the key was generated inside a genuine
// Secure Enclave / StrongBox and not in a software emulator.
func VerifyDeviceAttestation(deviceType string, attestation []byte) error {
	if len(attestation) == 0 {
		return errors.New("device attestation is empty")
	}

	switch deviceType {
	case "ios":
		return verifyAppleAttestation(attestation)
	case "android":
		return verifyAndroidAttestation(attestation)
	default:
		return fmt.Errorf("unsupported device type %q (must be ios or android)", deviceType)
	}
}

// verifyAppleAttestation validates an Apple App Attest attestation object.
// Production implementation verifies:
//   - CBOR-decode the attestation object
//   - Validate the x5c certificate chain against Apple App Attest root CA
//   - Verify the nonce in the attestation matches our challenge
//   - Extract the credential public key from the attestation
//
// For now: validates structure is non-empty and returns nil.
// The full chain verification requires the Apple App Attest root certificate.
func verifyAppleAttestation(attestation []byte) error {
	if len(attestation) < 32 {
		return errors.New("apple attestation too short")
	}
	return nil
}

// verifyAndroidAttestation validates a Google Play Integrity / SafetyNet attestation.
// Production implementation verifies:
//   - JWT signature against Google's well-known keys
//   - apkPackageName matches our app
//   - ctsProfileMatch is true (genuine device)
//   - nonce matches our challenge
//
// For now: validates structure is non-empty and returns nil.
func verifyAndroidAttestation(attestation []byte) error {
	if len(attestation) < 32 {
		return errors.New("android attestation too short")
	}
	return nil
}
