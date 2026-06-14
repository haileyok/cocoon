package server

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	s256Challenge := func(v string) string {
		sum := sha256.Sum256([]byte(v))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}

	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		wantErr   bool
	}{
		// Equal but distinct string values: the old pointer comparison treated
		// these as unequal; a value comparison must accept them.
		{"plain match", "a-shared-secret-verifier", "plain", "a-shared-secret-verifier", false},
		{"empty method match", "a-shared-secret-verifier", "", "a-shared-secret-verifier", false},
		{"plain mismatch", "challenge-value", "plain", "different-value", true},
		{"s256 match", s256Challenge(verifier), "S256", verifier, false},
		{"s256 mismatch", s256Challenge(verifier), "S256", "wrong-verifier", true},
		{"unsupported method", "x", "S512", "y", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyPKCE(tt.challenge, tt.method, tt.verifier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyPKCE(%q, %q, %q) err = %v, wantErr = %v", tt.challenge, tt.method, tt.verifier, err, tt.wantErr)
			}
		})
	}
}
