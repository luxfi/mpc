package mpc

import (
	"testing"
)

func TestDedupMap_SeenReturnsFalseFirstTime(t *testing.T) {
	d := newDedupMap()
	defer d.stop()

	if d.seen("key1") {
		t.Fatal("expected false for first call to seen()")
	}
}

func TestDedupMap_SeenReturnsTrueForDuplicate(t *testing.T) {
	d := newDedupMap()
	defer d.stop()

	d.seen("key1")
	if !d.seen("key1") {
		t.Fatal("expected true for duplicate key")
	}
}

func TestDedupMap_DifferentKeysAreIndependent(t *testing.T) {
	d := newDedupMap()
	defer d.stop()

	d.seen("key1")
	if d.seen("key2") {
		t.Fatal("key2 should not be seen")
	}
}

func TestDedupMap_StopIsIdempotent(t *testing.T) {
	d := newDedupMap()
	d.stop()
	d.stop() // should not panic
}
