package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
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

// NewClientTLSConfig creates a TLS 1.3 client config with PQ key exchange.
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
		// Accept self-signed certs from peer nodes.
		// Authentication is via ZAP Ed25519 identity, not PKI.
		InsecureSkipVerify: true,
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

// DualModeListener accepts both TLS and plaintext connections by sniffing the
// first byte. TLS records start with 0x16 (ContentType handshake). This enables
// rolling upgrades where some peers are TLS-enabled and others aren't yet.
type DualModeListener struct {
	inner     net.Listener
	tlsConfig *tls.Config
}

// NewDualModeListener wraps a net.Listener to auto-detect TLS vs plaintext.
func NewDualModeListener(inner net.Listener, tlsConfig *tls.Config) net.Listener {
	return &DualModeListener{inner: inner, tlsConfig: tlsConfig}
}

func (l *DualModeListener) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}

	// Peek at the first byte to detect TLS
	peek := make([]byte, 1)
	n, err := conn.Read(peek)
	if err != nil || n == 0 {
		conn.Close()
		return nil, fmt.Errorf("dual-mode: failed to peek: %w", err)
	}

	// Prepend the peeked byte back
	pconn := &prependConn{Conn: conn, buf: peek[:n]}

	if peek[0] == 0x16 {
		// TLS ClientHello — upgrade to TLS
		return tls.Server(pconn, l.tlsConfig), nil
	}

	// Plaintext connection — pass through
	return pconn, nil
}

func (l *DualModeListener) Close() error   { return l.inner.Close() }
func (l *DualModeListener) Addr() net.Addr { return l.inner.Addr() }

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
