//go:build goexperiment.runtimesecret

package mpc

import "runtime/secret"

// withSecretErasure runs f inside runtime/secret.Do, which ensures that any
// temporary stack/register state produced by f is zeroed after f returns.
// This provides forward secrecy for key material used during MPC signing.
func withSecretErasure(f func()) { secret.Do(f) }
