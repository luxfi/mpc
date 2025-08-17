package e2e

import (
	"testing"
)

func TestXRPLSigning(t *testing.T) {
	t.Skip("XRPL test requires infrastructure update")

	// TODO: Re-enable when the following are fixed:
	// 1. SetupE2ETestSuite function
	// 2. createWallet helper function
	// 3. SignTxMessage.GetMessage() method
	// 4. E2ETestSuite.client field
}
