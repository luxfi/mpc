package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/pquerna/otp/totp"
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgName  string `json:"org_name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.OrgName == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "org_name, email, and password are required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if !isValidEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	slug := slugify(req.OrgName)
	hash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	tx, err := s.db.Pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback(r.Context())

	var orgID string
	err = tx.QueryRow(r.Context(),
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id`,
		req.OrgName, slug).Scan(&orgID)
	if err != nil {
		writeError(w, http.StatusConflict, "organization already exists")
		return
	}

	var userID string
	err = tx.QueryRow(r.Context(),
		`INSERT INTO users (org_id, email, password_hash, role) VALUES ($1, $2, $3, 'owner') RETURNING id`,
		orgID, req.Email, hash).Scan(&userID)
	if err != nil {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	accessToken, err := s.generateJWT(userID, orgID, "owner")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	refreshToken, err := s.generateRefreshToken(userID, orgID, "owner")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"user_id":       userID,
		"org_id":        orgID,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		MFACode  string `json:"mfa_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var userID, orgID, role, passwordHash string
	var mfaSecret *string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT u.id, u.org_id, u.role, u.password_hash, u.mfa_secret
		 FROM users u WHERE u.email = $1`, req.Email).
		Scan(&userID, &orgID, &role, &passwordHash, &mfaSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !checkPassword(passwordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Only enforce MFA if the secret is active (not pending setup verification)
	if mfaSecret != nil && *mfaSecret != "" && !strings.HasPrefix(*mfaSecret, "pending:") {
		if req.MFACode == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"mfa_required": true,
			})
			return
		}
		if !totp.Validate(req.MFACode, *mfaSecret) {
			writeError(w, http.StatusUnauthorized, "invalid MFA code")
			return
		}
	}

	accessToken, err := s.generateJWT(userID, orgID, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	refreshToken, err := s.generateRefreshToken(userID, orgID, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":       userID,
		"org_id":        orgID,
		"role":          role,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	claims, err := s.validateJWT(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	accessToken, err := s.generateJWT(claims.UserID, claims.OrgID, claims.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	refreshToken, err := s.generateRefreshToken(claims.UserID, claims.OrgID, claims.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r.Context())

	// Look up user email for the TOTP account name
	var email string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT email FROM users WHERE id = $1`, userID).Scan(&email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to look up user")
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "LuxMPC",
		AccountName: email,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	// Store the base32-encoded secret (not yet verified -- MFA not active until handleMFAVerify)
	_, err = s.db.Pool.Exec(r.Context(),
		`UPDATE users SET mfa_secret = NULL WHERE id = $1`, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Store pending secret in a separate column or use a convention:
	// We store it but MFA is only active after verification confirms the user can produce codes.
	// For simplicity, store with a "pending:" prefix; handleMFAVerify strips it on confirmation.
	pending := "pending:" + key.Secret()
	_, err = s.db.Pool.Exec(r.Context(),
		`UPDATE users SET mfa_secret = $1 WHERE id = $2`, pending, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":  key.Secret(),
		"otpauth": key.URL(),
	})
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r.Context())

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	// Retrieve the pending MFA secret
	var mfaSecret *string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT mfa_secret FROM users WHERE id = $1`, userID).Scan(&mfaSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if mfaSecret == nil || *mfaSecret == "" {
		writeError(w, http.StatusBadRequest, "MFA setup not initiated")
		return
	}

	// Extract secret -- may have "pending:" prefix from setup
	secret := *mfaSecret
	if strings.HasPrefix(secret, "pending:") {
		secret = strings.TrimPrefix(secret, "pending:")
	} else {
		// MFA is already active, nothing to verify
		writeError(w, http.StatusBadRequest, "MFA is already enabled")
		return
	}

	// Validate the TOTP code
	if !totp.Validate(req.Code, secret) {
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	// Activate MFA by storing the secret without the "pending:" prefix
	_, err = s.db.Pool.Exec(r.Context(),
		`UPDATE users SET mfa_secret = $1 WHERE id = $2`, secret, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_enabled"})
}

func slugify(name string) string {
	s := strings.ToLower(name)
	s = regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

func isValidEmail(email string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`).MatchString(email)
}
