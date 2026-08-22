// Copyright © 2026 Lux Industries Inc. All rights reserved.

package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/reveal"
)

// groupHandler answers with the group key a caller seals to.
//
// It is public in the strict sense — it lets anyone seal a secret to this
// committee and lets nobody open one — but it is the one thing `mpcd seal`
// cannot work without, and until now nothing outside a node could read it.
//
// /keys cannot answer this. A KeyInfo record carries no org, so it cannot even
// name the share to read; and an empty eddsa_key there is silence about the
// curve rather than a denial of it, which is why 36 records reporting no
// Ed25519 key say nothing about whether the shares exist.
func groupHandler(store kvstore.KVStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		org := strings.TrimSpace(r.URL.Query().Get("org"))
		keyID := strings.TrimSpace(r.URL.Query().Get("key"))
		if org == "" || keyID == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "org and key are both required"})
			return
		}
		point, err := reveal.PublicKey(store, org, keyID)
		if err != nil {
			// A key this node holds no share for is a 404: the question is
			// answerable, and the answer is that there is nothing here.
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		raw, err := point.MarshalBinary()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		quorum, err := reveal.Quorum(store, org, keyID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"org":       org,
			"key":       keyID,
			"group_key": hex.EncodeToString(raw),
			"quorum":    quorum,
		})
	}
}
