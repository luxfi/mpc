package approval

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
)

// splitCommaTrim splits a comma-separated string and trims whitespace from
// each element. Empty fragments are dropped.
func splitCommaTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isHTTPSOrDev returns true iff origin is acceptable for WebAuthn binding.
// Production requires https://; dev allows http://localhost only when
// MPC_ENV=dev.
func isHTTPSOrDev(origin string) bool {
	if strings.HasPrefix(origin, "https://") {
		return true
	}
	env := strings.ToLower(os.Getenv("MPC_ENV"))
	if env != "dev" && env != "development" && env != "test" && env != "testing" {
		return false
	}
	return strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")
}

// splitWebAuthnSession parses a session ID of the form "approverID/digestB64".
// Returns approver ID, digest base64, error.
func splitWebAuthnSession(sessionID string) (string, string, error) {
	idx := strings.LastIndex(sessionID, "/")
	if idx <= 0 || idx == len(sessionID)-1 {
		return "", "", errors.New("approval/webauthn: malformed session id")
	}
	return sessionID[:idx], sessionID[idx+1:], nil
}

// encodeWebAuthnBundle serializes (authData || clientDataJSON || signature)
// with explicit length prefixes so a verifier can re-split exactly the
// same bytes the authenticator signed.
//
// Layout: [4-byte BE len(authData)] authData [4-byte BE len(clientData)] clientData [4-byte BE len(sig)] sig
func encodeWebAuthnBundle(authData, clientData, sig []byte) []byte {
	out := make([]byte, 0, 12+len(authData)+len(clientData)+len(sig))
	var buf4 [4]byte
	binary.BigEndian.PutUint32(buf4[:], uint32(len(authData)))
	out = append(out, buf4[:]...)
	out = append(out, authData...)
	binary.BigEndian.PutUint32(buf4[:], uint32(len(clientData)))
	out = append(out, buf4[:]...)
	out = append(out, clientData...)
	binary.BigEndian.PutUint32(buf4[:], uint32(len(sig)))
	out = append(out, buf4[:]...)
	out = append(out, sig...)
	return out
}

func decodeWebAuthnBundle(buf []byte) (authData, clientData, sig []byte, err error) {
	read := func(p *[]byte) ([]byte, error) {
		if len(*p) < 4 {
			return nil, errors.New("approval/webauthn: truncated bundle (length)")
		}
		n := binary.BigEndian.Uint32((*p)[:4])
		*p = (*p)[4:]
		if uint32(len(*p)) < n {
			return nil, errors.New("approval/webauthn: truncated bundle (payload)")
		}
		out := (*p)[:n]
		*p = (*p)[n:]
		return out, nil
	}
	cur := buf
	authData, err = read(&cur)
	if err != nil {
		return nil, nil, nil, err
	}
	clientData, err = read(&cur)
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err = read(&cur)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(cur) != 0 {
		return nil, nil, nil, errors.New("approval/webauthn: trailing bytes in bundle")
	}
	return authData, clientData, sig, nil
}
