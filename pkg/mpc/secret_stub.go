//go:build !goexperiment.runtimesecret

package mpc

import "runtime"

// withSecretErasure runs f then forces a GC to reclaim stack frames that held
// secret material. This is weaker than runtime/secret (which zeroes registers
// and stack slots) but still reduces the window for forensic memory extraction.
func withSecretErasure(f func()) {
	f()
	runtime.GC()
}
