package server

import "golang.org/x/crypto/bcrypt"

// comparePassword checks a password against an account's stored hash, like
// bcrypt.CompareHashAndPassword. An account with no password (one that signs
// in with a key) has an empty hash, and nothing ever matches it: this says so
// outright rather than relying on bcrypt rejecting an empty hash.
func comparePassword(hash, password string) error {
	if hash == "" {
		return bcrypt.ErrMismatchedHashAndPassword
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// passwordMatches reports whether a password matches an account's stored
// hash.
func passwordMatches(hash, password string) bool { return comparePassword(hash, password) == nil }
