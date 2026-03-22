//go:build !goexperiment.runtimesecret

package mpc

// withSecretErasure is a no-op stub when runtime/secret is not available.
// The signing operation runs identically; secret erasure is simply skipped.
func withSecretErasure(f func()) { f() }
