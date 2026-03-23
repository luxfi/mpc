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
// using the org-scoped key first. If orgID is non-empty and the org-scoped
// key is not found, it falls back to the legacy (unscoped) key for backward
// compatibility with shares generated before multi-tenancy.
func GetKeyShareWithFallback(store kvstore.KVStore, orgID, baseKey string) ([]byte, error) {
	if orgID != "" {
		scopedKey := OrgScopedKey(orgID, baseKey)
		data, err := store.Get(scopedKey)
		if err == nil {
			return data, nil
		}
		// Fall back to legacy key
	}
	return store.Get(baseKey)
}
