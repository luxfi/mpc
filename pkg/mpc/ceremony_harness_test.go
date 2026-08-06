package mpc

import (
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/mpc/internal/ceremony"
)

// The in-process ceremony driver itself lives in internal/ceremony, shared with
// cmd/mpcd's end-to-end signing tests. These wrappers only add the test-failure
// reporting, so both packages drive the identical protocol.

// ceremonyParties is a 2-of-3 committee: the smallest shape where a signing
// subset is a strict subset of the keygen set, so Lagrange interpolation is
// genuinely exercised rather than degenerating into a single share.
func ceremonyParties() []party.ID { return ceremony.Parties() }

// runCeremony drives a threshold protocol to completion entirely in-process.
//
// This is the same StartFunc the daemon's sessions hand to protocol.NewHandler,
// so the cryptographic output is the production output — only NATS, the kvstore,
// and the peer registry are absent.
func runCeremony(
	t *testing.T,
	ids []party.ID,
	sessionID []byte,
	start func(party.ID) protocol.StartFunc,
) map[party.ID]any {
	t.Helper()
	results, err := ceremony.Run(ids, sessionID, start)
	require.NoError(t, err)
	return results
}
