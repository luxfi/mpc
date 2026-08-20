package kms

import "testing"

// The key that protects a share must come from something secret. Without a
// client secret there is nothing secret to derive from — a key derived from the
// project id is computable by anyone who knows it, and a share protected that
// way is readable by them. So there is no client rather than a weak one.
func TestNoCredentialsMeansNoClient(t *testing.T) {
	if _, err := NewKMSClient(KMSConfig{ProjectID: "hanzo", Environment: "prod"}); err == nil {
		t.Fatal("a client was built with no credentials — its key is derivable from the project id")
	}
	if _, err := NewKMSClient(KMSConfig{ProjectID: "hanzo", ClientID: "id"}); err == nil {
		t.Fatal("a client was built with an id but no secret")
	}
	if _, err := NewKMSClient(KMSConfig{ProjectID: "hanzo", ClientSecret: "s"}); err == nil {
		t.Fatal("a client was built with a secret but no id")
	}
}

// The paired control: real credentials still build, so the refusal is about
// having nothing to derive from and not about the constructor being shut.
func TestRealCredentialsStillBuild(t *testing.T) {
	c, err := NewKMSClient(KMSConfig{ProjectID: "hanzo", ClientID: "id", ClientSecret: "a-real-secret"})
	if err != nil {
		t.Fatalf("credentials were refused: %v", err)
	}
	if len(c.masterKey) != 32 {
		t.Fatalf("master key is %d bytes, want 32", len(c.masterKey))
	}
}
