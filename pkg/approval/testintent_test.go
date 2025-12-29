package approval

import "crypto/sha256"

// testIntent is a tiny CanonicalIntent stand-in for the approval tests so
// they don't need pkg/intent (still being authored by a sibling task).
// Identical interface contract: Digest() returns 32 bytes, Bytes() returns
// the canonical pre-image.
type testIntent struct {
	body []byte
}

func newTestIntent(s string) *testIntent {
	return &testIntent{body: []byte(s)}
}

func (t *testIntent) Digest() [32]byte { return sha256.Sum256(t.body) }
func (t *testIntent) Bytes() []byte    { return t.body }
