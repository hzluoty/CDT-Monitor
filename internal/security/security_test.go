package security

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("Correct-Horse-42!")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "Correct-Horse-42!") {
		t.Fatal("expected password to verify")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("wrong password must not verify")
	}
}

func TestLegacyShortPasswordCanBeUpgraded(t *testing.T) {
	hash, err := HashLegacyPassword("short")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "short") {
		t.Fatal("legacy short password should still verify during migration")
	}
}

func TestCipherPersistsMasterKey(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := first.Encrypt("sensitive-value")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := second.Decrypt(encrypted)
	if err != nil || plain != "sensitive-value" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil || info.Size() == 0 {
		t.Fatal("master key was not persisted")
	}
}

func TestCipherLoadsMasterKeyFromEnvWithoutTouchingDisk(t *testing.T) {
	rawKey := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("CDT_MASTER_KEY", base64.StdEncoding.EncodeToString(rawKey))
	dir := filepath.Join(t.TempDir(), "nonexistent")

	first, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := first.Encrypt("serverless-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected no disk directory to be created when CDT_MASTER_KEY is set, got err=%v", err)
	}

	t.Setenv("CDT_MASTER_KEY", base64.RawURLEncoding.EncodeToString(rawKey))
	second, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := second.Decrypt(encrypted)
	if err != nil || plain != "serverless-secret" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
}
