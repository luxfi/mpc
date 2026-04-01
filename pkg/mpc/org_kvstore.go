package mpc

import (
	"fmt"
	"strings"

	"github.com/luxfi/mpc/pkg/kvstore"
)

// OrgScopedKey returns the org-namespaced kvstore key.
// Format: "org:<orgID>:<baseKey>" when orgID is non-empty,
// otherwise returns baseKey unchanged (legacy behavior).
func OrgScopedKey(orgID, baseKey string) string {
	if orgID == "" {
		return baseKey
	}
	if strings.Contains(orgID, ":") {
		// Sanitize: replace colons to prevent key injection
		orgID = strings.ReplaceAll(orgID, ":", "_")
	}
	return fmt.Sprintf("org:%s:%s", orgID, baseKey)
}

// GetKeyShareWithFallback attempts to load a key share from the kvstore
// using the org-scoped key when orgID is non-empty. When orgID is provided,
// only the org-scoped key is checked -- no fallback to the unscoped key is
// performed, preventing cross-tenant data leakage.
//
// When orgID is empty (truly unscoped callers), the legacy unscoped key is
// used directly. A warning is logged for this case so operators can migrate.
func GetKeyShareWithFallback(store kvstore.KVStore, orgID, baseKey string) ([]byte, error) {
	// Fail-closed on empty/whitespace orgID. No legacy fallback to unscoped keys.
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("orgID is required; unscoped key access is disabled")
	}
	scopedKey := OrgScopedKey(orgID, baseKey)
	return store.Get(scopedKey)
}
