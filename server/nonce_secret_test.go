package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/dpop"
)

// TestLoadOrCreateNonceSecretCreatesAndPersists covers the first boot: no file
// yet, so a secret is generated, written, and handed back to the caller.
func TestLoadOrCreateNonceSecretCreatesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonce.secret")

	secret, err := LoadOrCreateNonceSecret(path, nil)
	if err != nil {
		t.Fatalf("LoadOrCreateNonceSecret: %v", err)
	}

	if len(secret) != constants.NonceSecretByteLength {
		t.Fatalf("got a %d byte secret, want %d", len(secret), constants.NonceSecretByteLength)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted secret: %v", err)
	}

	if string(onDisk) != string(secret) {
		t.Fatal("persisted secret does not match the returned secret")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat persisted secret: %v", err)
	}

	if perm := info.Mode().Perm(); perm != nonceSecretFileMode {
		t.Fatalf("secret file mode = %04o, want %04o", perm, nonceSecretFileMode)
	}
}

// TestLoadOrCreateNonceSecretReusesExistingSecret covers every restart after the
// first: the file already exists and must be used verbatim. This is the
// regression test for the bug where the secret was written to a path the next
// process never read, so every restart rotated it and broke live OAuth sessions.
func TestLoadOrCreateNonceSecretReusesExistingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonce.secret")

	first, err := LoadOrCreateNonceSecret(path, nil)
	if err != nil {
		t.Fatalf("first LoadOrCreateNonceSecret: %v", err)
	}

	second, err := LoadOrCreateNonceSecret(path, nil)
	if err != nil {
		t.Fatalf("second LoadOrCreateNonceSecret: %v", err)
	}

	if string(first) != string(second) {
		t.Fatal("a restart produced a different nonce secret")
	}
}

// TestIssuedNonceSurvivesRestart is the behaviour the secret exists for: a nonce
// minted before a restart must still be accepted afterwards. The second half is
// a negative control proving the assertion is meaningful, since a nonce is only
// accepted when the signing secret is identical.
func TestIssuedNonceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonce.secret")
	rotation := time.Hour

	beforeRestart, err := LoadOrCreateNonceSecret(path, nil)
	if err != nil {
		t.Fatalf("LoadOrCreateNonceSecret before restart: %v", err)
	}

	issued := dpop.NewNonce(dpop.NonceArgs{Secret: beforeRestart, RotationInterval: rotation}).NextNonce()

	afterRestart, err := LoadOrCreateNonceSecret(path, nil)
	if err != nil {
		t.Fatalf("LoadOrCreateNonceSecret after restart: %v", err)
	}

	restarted := dpop.NewNonce(dpop.NonceArgs{Secret: afterRestart, RotationInterval: rotation})
	if !restarted.Check(issued) {
		t.Fatal("a nonce issued before the restart is no longer accepted after it")
	}

	fresh := dpop.NewNonce(dpop.NonceArgs{
		Secret:           []byte(strings.Repeat("x", constants.NonceSecretByteLength)),
		RotationInterval: rotation,
	})
	if fresh.Check(issued) {
		t.Fatal("a nonce signed with a different secret was accepted")
	}
}

// TestLoadOrCreateNonceSecretReplacesUnusableFile guards the truncated/empty file
// case: loading one as a secret would break every session at the next restart.
func TestLoadOrCreateNonceSecretReplacesUnusableFile(t *testing.T) {
	for name, contents := range map[string]string{
		"empty":        "",
		"short":        "too-short",
		"overlength":   strings.Repeat("y", constants.NonceSecretByteLength+1),
		"single byte ": "z",
	} {
		t.Run(strings.TrimSpace(name), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nonce.secret")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("seed secret file: %v", err)
			}

			secret, err := LoadOrCreateNonceSecret(path, nil)
			if err != nil {
				t.Fatalf("LoadOrCreateNonceSecret: %v", err)
			}

			if len(secret) != constants.NonceSecretByteLength {
				t.Fatalf("got a %d byte secret, want %d", len(secret), constants.NonceSecretByteLength)
			}

			if string(secret) == contents {
				t.Fatal("the unusable file contents were returned as the secret")
			}

			onDisk, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read persisted secret: %v", err)
			}

			if string(onDisk) != string(secret) {
				t.Fatal("the replacement secret was not persisted")
			}
		})
	}
}

// TestLoadOrCreateNonceSecretCreatesParentDirectory keeps a first run against a
// not-yet-created volume subdirectory working.
func TestLoadOrCreateNonceSecretCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "nested", "nonce.secret")

	secret, err := LoadOrCreateNonceSecret(path, nil)
	if err != nil {
		t.Fatalf("LoadOrCreateNonceSecret: %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted secret: %v", err)
	}

	if string(onDisk) != string(secret) {
		t.Fatal("persisted secret does not match the returned secret")
	}
}

func TestLoadOrCreateNonceSecretErrors(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		if _, err := LoadOrCreateNonceSecret("", nil); err == nil {
			t.Fatal("expected an error for an empty path")
		}
	})

	t.Run("path is a directory", func(t *testing.T) {
		secret, err := LoadOrCreateNonceSecret(t.TempDir(), nil)
		if err == nil {
			t.Fatal("expected an error when the path is a directory")
		}

		if secret != nil {
			t.Fatal("expected no secret alongside the error")
		}
	})
}

func TestSaveNonceSecretRejectsWrongLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonce.secret")

	if err := SaveNonceSecret(path, []byte("short")); err == nil {
		t.Fatal("expected an error for a wrong-length secret")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a rejected secret should not be written to disk")
	}
}

// TestSaveNonceSecretLeavesNoTemporaryFiles proves the temp-file-and-rename
// write cleans up after itself, so a secret directory doesn't accumulate
// half-written files that confuse the next run.
func TestSaveNonceSecretLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonce.secret")

	if err := SaveNonceSecret(path, []byte(strings.Repeat("a", constants.NonceSecretByteLength))); err != nil {
		t.Fatalf("SaveNonceSecret: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	if len(entries) != 1 || entries[0].Name() != "nonce.secret" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected directory contents: %v", names)
	}
}

func TestResolveNonceSecretPath(t *testing.T) {
	if got := resolveNonceSecretPath(""); got != DefaultNonceSecretPath {
		t.Fatalf("empty path resolved to %q, want %q", got, DefaultNonceSecretPath)
	}

	if got := resolveNonceSecretPath("/data/cocoon/nonce.secret"); got != "/data/cocoon/nonce.secret" {
		t.Fatalf("configured path was not preserved: %q", got)
	}
}

// TestComposeFilesPersistTheNonceSecret keeps the deployment config honest. The
// production symptom (clients stuck re-authorizing after every restart) comes
// from a secret that is written somewhere the next container does not read, and
// the image's working directory is `/`, so compose has to point the path at a
// mounted volume.
func TestComposeFilesPersistTheNonceSecret(t *testing.T) {
	for _, name := range []string{"docker-compose.yaml", "docker-compose.postgres.yaml", "docker-compose.noproxy.yaml"} {
		body, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		if !strings.Contains(string(body), "COCOON_NONCE_SECRET_PATH") {
			t.Errorf("%s does not set COCOON_NONCE_SECRET_PATH, so the nonce secret dies with the container", name)
		}

		if !strings.Contains(string(body), "/data/cocoon/nonce.secret") {
			t.Errorf("%s does not put the nonce secret on the mounted volume", name)
		}
	}
}
