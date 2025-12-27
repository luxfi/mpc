package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// oidcUserInfo represents the response from an OIDC userinfo endpoint.
type oidcUserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername  string `json:"preferred_username"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	DisplayName       string `json:"displayName"`
}

// handleOIDCExchange exchanges an external OIDC access token for a local MPC API JWT.
// POST /api/v1/auth/oidc
// Body: {"access_token": "...", "provider_url": "https://lux.id"}
func (s *Server) handleOIDCExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken string `json:"access_token"`
		ProviderURL string `json:"provider_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AccessToken == "" {
		writeError(w, http.StatusBadRequest, "access_token is required")
		return
	}
	if req.ProviderURL == "" {
		writeError(w, http.StatusBadRequest, "provider_url is required")
		return
	}

	// Validate provider is in the allowlist
	if !s.isAllowedOIDCIssuer(req.ProviderURL) {
		writeError(w, http.StatusBadRequest, "provider not allowed")
		return
	}

	// Call the provider's userinfo endpoint
	userInfo, err := fetchUserInfo(req.ProviderURL, req.AccessToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "failed to validate token: "+err.Error())
		return
	}
	if userInfo.Email == "" {
		writeError(w, http.StatusUnauthorized, "provider did not return an email")
		return
	}

	// Find or create user by email
	user, orgID, err := s.findOrCreateOIDCUser(r, userInfo)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to provision user: "+err.Error())
		return
	}

	userID := user.Id()
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
		"email":         userInfo.Email,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// fetchUserInfo calls the OIDC provider's userinfo endpoint to validate the token.
func fetchUserInfo(providerURL, accessToken string) (*oidcUserInfo, error) {
	userinfoURL := strings.TrimRight(providerURL, "/") + "/oauth/userinfo"

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo returned %d: %s", resp.StatusCode, string(body))
	}

	var info oidcUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo: %w", err)
	}
	return &info, nil
}

// findOrCreateOIDCUser looks up a user by email or auto-provisions them.
func (s *Server) findOrCreateOIDCUser(r *http.Request, info *oidcUserInfo) (*db.User, string, error) {
	// Try to find existing user
	existing, err := orm.TypedQuery[db.User](s.db.ORM).
		Filter("email=", info.Email).
		First()
	if err == nil && existing != nil {
		return existing, existing.OrgID, nil
	}

	// Auto-provision: create org + user
	displayName := info.Name
	if displayName == "" {
		displayName = info.DisplayName
	}
	if displayName == "" {
		displayName = info.PreferredUsername
	}
	if displayName == "" {
		displayName = strings.Split(info.Email, "@")[0]
	}

	orgName := displayName + "'s Org"
	slug := slugify(orgName)

	var orgID, userID string
	err = s.db.ORM.RunInTransaction(r.Context(), func(tx orm.DB) error {
		org := orm.New[db.Organization](tx)
		org.Name = orgName
		org.Slug = slug
		if err := org.Create(); err != nil {
			return err
		}
		orgID = org.Id()

		user := orm.New[db.User](tx)
		user.OrgID = orgID
		user.Email = info.Email
		user.PasswordHash = "" // OIDC users don't have local passwords
		user.Role = "owner"
		if err := user.Create(); err != nil {
			return err
		}
		userID = user.Id()
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("provision failed: %w", err)
	}

	user, err := orm.Get[db.User](s.db.ORM, userID)
	if err != nil {
		return nil, "", err
	}
	return user, orgID, nil
}

func (s *Server) isAllowedOIDCIssuer(url string) bool {
	normalized := strings.TrimRight(url, "/")
	for _, issuer := range s.oidcIssuers {
		if strings.TrimRight(issuer, "/") == normalized {
			return true
		}
	}
	return false
}
