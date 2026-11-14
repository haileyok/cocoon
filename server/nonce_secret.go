package server

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/oauth/constants"
)

// DefaultNonceSecretPath is the DPoP nonce secret location used when
// NonceSecretPath is empty. It is resolved against the process working
// directory, which only survives a restart when that directory is on a mounted
// volume, so container deployments should set NonceSecretPath explicitly.
const DefaultNonceSecretPath = "nonce.secret"

// nonceSecretFileMode keeps the secret readable only by the user running the
// server. It is a signing key: another local user holding it can forge nonces.
const nonceSecretFileMode fs.FileMode = 0o600

// resolveNonceSecretPath applies the default when the configured path is empty.
func resolveNonceSecretPath(configured string) string {
	if configured == "" {
		return DefaultNonceSecretPath
	}

	return configured
}

// LoadOrCreateNonceSecret returns the DPoP nonce secret stored at path,
// generating and persisting one when it is missing or unusable.
//
// The secret signs the short-lived DPoP nonces handed to OAuth clients, so it
// has to outlive the process: a new secret invalidates every nonce a client
// already holds, which makes its next request fail with use_dpop_nonce and can
// leave the client stuck re-authorizing (or, worse, retrying the same stale
// nonce forever). Point path at durable storage, and reuse the same value
// across replicas.
//
// A secret file that is present but the wrong length is treated as unusable
// and replaced, because a truncated or empty file would otherwise be loaded as
// a nil secret and silently break every session on the next restart.
func LoadOrCreateNonceSecret(path string, logger *slog.Logger) ([]byte, error) {
	if path == "" {
		return nil, errors.New("nonce secret path is empty")
	}

	if logger == nil {
		logger = slog.Default()
	}

	secret, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(secret) == constants.NonceSecretByteLength {
			return secret, nil
		}

		logger.Warn("nonce secret file has an unexpected length, replacing it. every client will have to authorize again",
			"path", path,
			"length", len(secret),
			"expected", constants.NonceSecretByteLength,
		)
	case errors.Is(err, fs.ErrNotExist):
		logger.Info("no dpop nonce secret yet, creating one", "path", path)
	default:
		return nil, fmt.Errorf("read nonce secret %q: %w", path, err)
	}

	generated := helpers.RandomBytes(constants.NonceSecretByteLength)
	if err := SaveNonceSecret(path, generated); err != nil {
		return nil, err
	}

	return generated, nil
}

// SaveNonceSecret writes secret to path with owner-only permissions.
//
// The write goes through a temporary file in the same directory and a rename,
// so a crash mid-write cannot leave a truncated secret behind: readers either
// see the previous secret or the new one.
func SaveNonceSecret(path string, secret []byte) error {
	if path == "" {
		return errors.New("nonce secret path is empty")
	}

	if len(secret) != constants.NonceSecretByteLength {
		return fmt.Errorf("nonce secret must be %d bytes, got %d", constants.NonceSecretByteLength, len(secret))
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create nonce secret directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".nonce.secret-*")
	if err != nil {
		return fmt.Errorf("create temporary nonce secret in %q: %w", dir, err)
	}

	tmpName := tmp.Name()
	// Best effort: after a successful rename this removes a path that no longer
	// exists, and on any error path it cleans up the partial file.
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(nonceSecretFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set nonce secret permissions: %w", err)
	}

	if _, err := tmp.Write(secret); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write nonce secret: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync nonce secret: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close nonce secret: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("persist nonce secret to %q: %w", path, err)
	}

	return nil
}
