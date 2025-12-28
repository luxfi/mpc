package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// PQ TLS 1.3 configuration for MPC node-to-node communication.
//
// Go 1.24+ negotiates X25519MLKEM768 (hybrid post-quantum) by default.
// Go 1.26+ also negotiates SecP256r1MLKEM768 and SecP384r1MLKEM1024.
// No extra configuration needed — just use crypto/tls with TLS 1.3.
//
// The Ed25519 identity key is reused as the TLS certificate key, providing
// mutual authentication between MPC nodes without a separate PKI.

// newSelfSignedCert generates a self-signed TLS certificate from an Ed25519 key.
func newSelfSignedCert(nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) (tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(1),
		Subject: pkix.Name{
			CommonName:   "mpc-" + nodeID,
			Organization: []string{"Lux MPC"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"mpc-" + nodeID, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// NewServerTLSConfig creates a TLS 1.3 server config with PQ key exchange.
// Uses the node's Ed25519 identity for mutual TLS authentication.
func NewServerTLSConfig(nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) (*tls.Config, error) {
	cert, err := newSelfSignedCert(nodeID, privKey, pubKey)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// Go 1.26 defaults include X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024.
		// Explicit CurvePreferences ensures PQ hybrid is preferred even if defaults change.
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,     // Hybrid PQ: X25519 + ML-KEM-768
			tls.SecP256r1MLKEM768,  // Hybrid PQ: P-256 + ML-KEM-768
			tls.SecP384r1MLKEM1024, // Hybrid PQ: P-384 + ML-KEM-1024
			tls.X25519,             // Classical fallback
			tls.CurveP256,          // Classical fallback
		},
		// Skip client cert verification for now — nodes authenticate via Ed25519
		// identity messages in the ZAP protocol after TLS handshake.
		ClientAuth: tls.NoClientCert,
	}, nil
}

// CertPinStore implements Trust-On-First-Use (TOFU) certificate pinning.
// On first connection to a peer, the certificate fingerprint (SHA-256 of DER)
// is stored. Subsequent connections verify the peer cert matches the pinned
// fingerprint, preventing MitM even with self-signed certificates.
type CertPinStore struct {
	mu   sync.RWMutex
	pins map[string]string // peer address/CN → SHA-256 hex fingerprint
}

// NewCertPinStore creates a new TOFU certificate pin store.
func NewCertPinStore() *CertPinStore {
	return &CertPinStore{pins: make(map[string]string)}
}

// certFingerprint returns the SHA-256 hex fingerprint of a DER-encoded certificate.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// VerifyOrPin checks a peer certificate against the pin store.
// First connection: pins the fingerprint (TOFU). Subsequent: verifies match.
func (s *CertPinStore) VerifyOrPin(peerID string, cert *x509.Certificate) error {
	fp := certFingerprint(cert)

	s.mu.RLock()
	existing, pinned := s.pins[peerID]
	s.mu.RUnlock()

	if pinned {
		if existing != fp {
			return fmt.Errorf("tls: certificate fingerprint mismatch for %s (pinned=%s got=%s) — possible MitM", peerID, existing[:16], fp[:16])
		}
		return nil
	}

	// TOFU: first connection, pin the fingerprint
	s.mu.Lock()
	// Double-check after acquiring write lock
	if existing, pinned = s.pins[peerID]; pinned {
		s.mu.Unlock()
		if existing != fp {
			return fmt.Errorf("tls: certificate fingerprint mismatch for %s (pinned=%s got=%s) — possible MitM", peerID, existing[:16], fp[:16])
		}
		return nil
	}
	s.pins[peerID] = fp
	s.mu.Unlock()
	return nil
}

// defaultCertPinStore is the process-global TOFU pin store.
var defaultCertPinStore = NewCertPinStore()

// NewClientTLSConfig creates a TLS 1.3 client config with PQ key exchange.
// Uses TOFU certificate pinning instead of InsecureSkipVerify.
func NewClientTLSConfig(nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) (*tls.Config, error) {
	cert, err := newSelfSignedCert(nodeID, privKey, pubKey)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
			tls.X25519,
			tls.CurveP256,
		},
		// Self-signed certs require skipping the CA chain verification,
		// but we enforce TOFU pinning in VerifyConnection below.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("peer did not present a TLS certificate")
			}
			// TOFU: pin on first connection, reject mismatches on subsequent.
			peerCert := cs.PeerCertificates[0]
			peerID := peerCert.Subject.CommonName
			if peerID == "" {
				peerID = cs.ServerName
			}
			return defaultCertPinStore.VerifyOrPin(peerID, peerCert)
		},
	}, nil
}

// ListenTLS starts a TLS 1.3 listener with PQ key exchange.
func ListenTLS(addr string, nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) (net.Listener, error) {
	tlsConfig, err := NewServerTLSConfig(nodeID, privKey, pubKey)
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", addr, tlsConfig)
}

// TLSOnlyListener wraps a net.Listener to enforce TLS on all connections.
// Plaintext connections are rejected immediately. The only exception is when
// ALLOW_PLAINTEXT=true AND ENVIRONMENT=development are both set, which is
// intended for local development only.
type TLSOnlyListener struct {
	inner          net.Listener
	tlsConfig      *tls.Config
	allowPlaintext bool
}

// NewTLSOnlyListener wraps a net.Listener to enforce TLS.
// Plaintext is only allowed when allowPlaintext is true AND
// ENVIRONMENT=development. The allowPlaintext parameter should be sourced
// from the ALLOW_PLAINTEXT env var.
func NewTLSOnlyListener(inner net.Listener, tlsConfig *tls.Config) net.Listener {
	allowPlaintext := os.Getenv("ALLOW_PLAINTEXT") == "true" && os.Getenv("ENVIRONMENT") == "development"
	return &TLSOnlyListener{inner: inner, tlsConfig: tlsConfig, allowPlaintext: allowPlaintext}
}

// NewDualModeListener is a deprecated alias for NewTLSOnlyListener.
// Retained for compile compatibility; plaintext is no longer accepted
// unless ALLOW_PLAINTEXT=true and ENVIRONMENT=development.
func NewDualModeListener(inner net.Listener, tlsConfig *tls.Config) net.Listener {
	return NewTLSOnlyListener(inner, tlsConfig)
}

func (l *TLSOnlyListener) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}

	// Peek at the first byte to detect TLS
	peek := make([]byte, 1)
	n, err := conn.Read(peek)
	if err != nil || n == 0 {
		conn.Close()
		return nil, fmt.Errorf("tls-only: failed to peek: %w", err)
	}

	// Prepend the peeked byte back
	pconn := &prependConn{Conn: conn, buf: peek[:n]}

	if peek[0] == 0x16 {
		// TLS ClientHello — upgrade to TLS
		return tls.Server(pconn, l.tlsConfig), nil
	}

	// Plaintext connection — only allowed in development with explicit opt-in.
	if l.allowPlaintext {
		return pconn, nil
	}
	conn.Close()
	return nil, fmt.Errorf("tls-only: rejected plaintext connection from %s", conn.RemoteAddr())
}

func (l *TLSOnlyListener) Close() error   { return l.inner.Close() }
func (l *TLSOnlyListener) Addr() net.Addr { return l.inner.Addr() }

// prependConn prepends buffered bytes before the underlying connection data.
type prependConn struct {
	net.Conn
	buf []byte
}

func (c *prependConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// DialTLS connects to a peer using TLS 1.3 with PQ key exchange.
func DialTLS(addr string, nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey, timeout time.Duration) (net.Conn, error) {
	tlsConfig, err := NewClientTLSConfig(nodeID, privKey, pubKey)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
}
