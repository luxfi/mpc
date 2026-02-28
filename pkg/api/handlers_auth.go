package api

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
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

	if mfaSecret != nil && *mfaSecret != "" {
		if req.MFACode == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"mfa_required": true,
			})
			return
		}
		// TODO: validate TOTP code against mfaSecret
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

	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate secret")
		return
	}
	encoded := base32.StdEncoding.EncodeToString(secret)

	_, err := s.db.Pool.Exec(r.Context(),
		`UPDATE users SET mfa_secret = $1 WHERE id = $2`, encoded, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":   encoded,
		"otpauth":  "otpauth://totp/LuxMPC?secret=" + encoded + "&issuer=LuxMPC",
	})
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// TODO: Implement TOTP verification
	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
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
