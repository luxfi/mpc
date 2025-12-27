package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
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

	var orgID, userID string
	err = s.db.ORM.RunInTransaction(r.Context(), func(tx orm.DB) error {
		org := orm.New[db.Organization](tx)
		org.Name = req.OrgName
		org.Slug = slug
		if err := org.Create(); err != nil {
			return err
		}
		orgID = org.Id()

		user := orm.New[db.User](tx)
		user.OrgID = orgID
		user.Email = req.Email
		user.PasswordHash = hash
		user.Role = "owner"
		if err := user.Create(); err != nil {
			return err
		}
		userID = user.Id()
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, "organization or email already exists")
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

	user, err := orm.TypedQuery[db.User](s.db.ORM).
		Filter("email=", req.Email).
		First()
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !checkPassword(user.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Only enforce MFA if the secret is active (not pending setup verification)
	if user.MFASecret != nil && *user.MFASecret != "" && !strings.HasPrefix(*user.MFASecret, "pending:") {
		if req.MFACode == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"mfa_required": true,
			})
			return
		}
		if !totp.Validate(req.MFACode, *user.MFASecret) {
			writeError(w, http.StatusUnauthorized, "invalid MFA code")
			return
		}
	}

	userID := user.Id()
	orgID := user.OrgID
	role := user.Role

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

	user, err := orm.Get[db.User](s.db.ORM, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to look up user")
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "LuxMPC",
		AccountName: user.Email,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	// Store pending secret (not yet verified — MFA not active until handleMFAVerify)
	pending := "pending:" + key.Secret()
	user.MFASecret = &pending
	if err := user.Update(); err != nil {
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

	user, err := orm.Get[db.User](s.db.ORM, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user.MFASecret == nil || *user.MFASecret == "" {
		writeError(w, http.StatusBadRequest, "MFA setup not initiated")
		return
	}

	secret := *user.MFASecret
	if strings.HasPrefix(secret, "pending:") {
		secret = strings.TrimPrefix(secret, "pending:")
	} else {
		writeError(w, http.StatusBadRequest, "MFA is already enabled")
		return
	}

	if !totp.Validate(req.Code, secret) {
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	// Activate MFA
	user.MFASecret = &secret
	if err := user.Update(); err != nil {
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
