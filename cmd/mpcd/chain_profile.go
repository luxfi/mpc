// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"fmt"
	"strings"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

// chain_profile.go — mpcd's chain-profile posture for the embedded
// threshold dispatcher's strict-PQ gate (closes Red M-2).
//
// The threshold dispatcher's Sign_Ctx_Profile consults a
// thresholdd.ChainProfileResolver before allowing the single-party
// dealer / single-validator shortcut on a ctx-bound classical-shape
// primitive (pulsar.sign_ctx, magnetar.sign_ctx). With NO resolver
// wired the gate fails OPEN — every chainID, including strict-PQ
// chains, slips through (the M-2 finding). mpcd is the embedder the
// threshold package documents as the owner of this policy: it supplies
// the resolver from the node's configured posture so the gate fails
// CLOSED by default.
//
// Decomplected: this file owns ONLY the config→Profile mapping and the
// resolver construction. The gate mechanism (when to consult the
// resolver, what the refusal means) stays in luxfi/threshold. No
// bespoke resolver type, no luxfi/consensus/config dependency — we use
// the canonical thresholdd.NewStaticChainProfileResolver the package
// exposes precisely for embedders.
//
// Residual (empty chainID): thresholdd.RefuseUnderStrictPQ short-
// circuits to PASS when the client-supplied chainID is "" — BEFORE the
// resolver is consulted — so a context-less sign_ctx still slips the
// gate even on a strict-PQ node. That short-circuit lives inside the
// threshold gate, on a listener threshold owns; mpc cannot intercept
// it. The resolver built here is already fail-closed for the empty key
// (ResolveChainProfile("") == ProfileStrictPQ under a strict-PQ
// default), so the residual closes the instant the threshold gate
// routes "" through the resolver instead of special-casing it. See the
// Red Handoff note for the one-line threshold change.

// chainProfileFromString maps the operator-facing --chain-profile value
// to the thresholdd.Profile the strict-PQ gate reasons about.
//
// Fail-secure by construction: an empty / unset value resolves to
// ProfileStrictPQ. An mpcd node refuses the dealer shortcut on ctx-
// bound signing unless an operator deliberately downgrades posture
// (legacy-compat) or allow-lists specific chains (--legacy-chains).
//
// "fips" is an alias for strict-pq: luxfi/consensus/config ProfileFIPS
// (0x03) is IsPQ()==true and equally forbids the dealer shortcut.
func chainProfileFromString(s string) (thresholdd.Profile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "strict-pq", "strictpq", "strict", "pq", "fips":
		return thresholdd.ProfileStrictPQ, nil
	case "legacy-compat", "legacy", "permissive", "compat":
		return thresholdd.ProfileLegacyCompat, nil
	case "unknown", "open":
		return thresholdd.ProfileUnknown, nil
	default:
		return thresholdd.ProfileUnknown,
			fmt.Errorf("unrecognised chain-profile %q (want strict-pq|legacy-compat|unknown)", s)
	}
}

// buildChainProfileResolver constructs the ChainProfileResolver the
// embedded threshold dispatcher consults on every sign_ctx.
//
//   - def is the node-wide default posture (from --chain-profile): the
//     profile returned for any chainID NOT in the allow-list, including
//     the empty chainID.
//   - legacyChains is the explicit allow-list of chainIDs permitted the
//     dealer shortcut even when the node default is strict-PQ (e.g. a
//     dev / non-PQ chain co-served by a strict-PQ node).
//
// The returned resolver is the canonical
// thresholdd.NewStaticChainProfileResolver — concurrent-safe, no
// bespoke type.
func buildChainProfileResolver(def thresholdd.Profile, legacyChains []string) thresholdd.ChainProfileResolver {
	overrides := make(map[string]thresholdd.Profile, len(legacyChains))
	for _, id := range legacyChains {
		if id = strings.TrimSpace(id); id != "" {
			overrides[id] = thresholdd.ProfileLegacyCompat
		}
	}
	return thresholdd.NewStaticChainProfileResolver(def, overrides)
}

// splitCSV splits a comma- or space-separated flag value into trimmed,
// non-empty tokens. Empty input yields a nil slice.
func splitCSV(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
