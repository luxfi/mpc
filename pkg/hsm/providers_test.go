package hsm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvProvider(t *testing.T) {
	const testPassword = "test-password-12345"
	t.Setenv("LUX_MPC_PASSWORD", testPassword)

	p := &EnvProvider{}
	got, err := p.GetPassword(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testPassword {
		t.Errorf("got %q, want %q", got, testPassword)
	}
}

func TestEnvProviderCustomVar(t *testing.T) {
	const testPassword = "custom-password-67890"
	t.Setenv("MY_CUSTOM_PASSWORD", testPassword)

	p := &EnvProvider{EnvVar: "MY_CUSTOM_PASSWORD"}
	got, err := p.GetPassword(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testPassword {
		t.Errorf("got %q, want %q", got, testPassword)
	}
}

func TestEnvProviderFallbackToZAPDB(t *testing.T) {
	const testPassword = "zapdb-password-abc"
	// Clear primary var, set fallback
	t.Setenv("LUX_MPC_PASSWORD", "")
	t.Setenv("ZAPDB_PASSWORD", testPassword)

	p := &EnvProvider{}
	got, err := p.GetPassword(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testPassword {
		t.Errorf("got %q, want %q", got, testPassword)
	}
}

func TestEnvProviderEmpty(t *testing.T) {
	t.Setenv("LUX_MPC_PASSWORD", "")
	t.Setenv("ZAPDB_PASSWORD", "")

	p := &EnvProvider{}
	_, err := p.GetPassword(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty env var")
	}
}

func TestFileProvider(t *testing.T) {
	const testPassword = "file-password-xyz"

	dir := t.TempDir()
	path := filepath.Join(dir, "password.txt")
	if err := os.WriteFile(path, []byte(testPassword+"\n"), 0600); err != nil {
		t.Fatalf("failed to write password file: %v", err)
	}

	p := &FileProvider{Path: path}
	got, err := p.GetPassword(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testPassword {
		t.Errorf("got %q, want %q", got, testPassword)
	}
}

func TestFileProviderViaKeyID(t *testing.T) {
	const testPassword = "keyid-password"

	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte(testPassword), 0600); err != nil {
		t.Fatalf("failed to write password file: %v", err)
	}

	p := &FileProvider{}
	got, err := p.GetPassword(context.Background(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testPassword {
		t.Errorf("got %q, want %q", got, testPassword)
	}
}

func TestFileProviderMissing(t *testing.T) {
	p := &FileProvider{Path: "/nonexistent/path/to/password.txt"}
	_, err := p.GetPassword(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFileProviderEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	p := &FileProvider{Path: path}
	_, err := p.GetPassword(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty password file")
	}
}

func TestNewPasswordProviderDefaults(t *testing.T) {
	// Empty type should default to env
	p, err := NewPasswordProvider("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.(*EnvProvider); !ok {
		t.Errorf("expected *EnvProvider, got %T", p)
	}
}

func TestNewPasswordProviderAllTypes(t *testing.T) {
	tests := []struct {
		providerType string
		expectType   string
	}{
		{"aws", "*hsm.AWSKMSProvider"},
		{"gcp", "*hsm.GCPKMSProvider"},
		{"azure", "*hsm.AzureKVProvider"},
		{"env", "*hsm.EnvProvider"},
		{"file", "*hsm.FileProvider"},
	}

	for _, tt := range tests {
		t.Run(tt.providerType, func(t *testing.T) {
			p, err := NewPasswordProvider(tt.providerType, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p == nil {
				t.Fatal("expected non-nil provider")
			}
		})
	}
}

func TestNewPasswordProviderUnknown(t *testing.T) {
	_, err := NewPasswordProvider("unknown-provider", nil)
	if err == nil {
		t.Fatal("expected error for unknown provider type")
	}
}

func TestAWSKMSProviderNoCiphertext(t *testing.T) {
	t.Setenv("ZAPDB_ENCRYPTED_PASSWORD", "")

	p := &AWSKMSProvider{Region: "us-east-1"}
	_, err := p.GetPassword(context.Background(), "alias/test-key")
	if err == nil {
		t.Fatal("expected error when ZAPDB_ENCRYPTED_PASSWORD is empty")
	}
}

func TestGCPKMSProviderNoCiphertext(t *testing.T) {
	t.Setenv("ZAPDB_ENCRYPTED_PASSWORD", "")

	p := &GCPKMSProvider{
		ProjectID:   "test-project",
		LocationID:  "global",
		KeyRingID:   "test-ring",
		CryptoKeyID: "test-key",
	}
	_, err := p.GetPassword(context.Background(), "")
	if err == nil {
		t.Fatal("expected error when ZAPDB_ENCRYPTED_PASSWORD is empty")
	}
}

func TestAzureKVProviderNoCiphertext(t *testing.T) {
	t.Setenv("ZAPDB_ENCRYPTED_PASSWORD", "")

	p := &AzureKVProvider{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}
	_, err := p.GetPassword(context.Background(), "")
	if err == nil {
		t.Fatal("expected error when ZAPDB_ENCRYPTED_PASSWORD is empty")
	}
}

func TestGCPParseResourceName(t *testing.T) {
	name := "projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/my-key"
	parts := parseGCPKeyResourceName(name)
	if parts == nil {
		t.Fatal("expected non-nil parts")
	}
	if parts["project"] != "my-project" {
		t.Errorf("project: got %q, want %q", parts["project"], "my-project")
	}
	if parts["location"] != "us-east1" {
		t.Errorf("location: got %q, want %q", parts["location"], "us-east1")
	}
	if parts["keyRing"] != "my-ring" {
		t.Errorf("keyRing: got %q, want %q", parts["keyRing"], "my-ring")
	}
	if parts["cryptoKey"] != "my-key" {
		t.Errorf("cryptoKey: got %q, want %q", parts["cryptoKey"], "my-key")
	}
}

func TestSHA256Hex(t *testing.T) {
	// Known test vector: SHA-256 of empty string
	got := sha256Hex([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("sha256Hex(empty): got %q, want %q", got, want)
	}
}
