package server

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordMatches(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !passwordMatches(string(hash), "hunter2") {
		t.Fatal("the right password was refused")
	}
	if passwordMatches(string(hash), "wrong") {
		t.Fatal("a wrong password was accepted")
	}
	// An account with no password (one that signs in with a key) never
	// matches, whatever is offered.
	for _, offered := range []string{"", "hunter2", " "} {
		if passwordMatches("", offered) {
			t.Fatalf("an account with no password matched %q", offered)
		}
	}
}
