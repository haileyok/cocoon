package main

import (
	"os"
	"regexp"
	"testing"
)

// Go 1.24 changed the multipathtcp GODEBUG default to "2", which turns every
// listening TCP socket on Linux into a Multipath TCP listener. Cocoon speaks
// plain TCP and never asks for MPTCP, so the listener buys us nothing while
// giving remote peers a much larger slice of the kernel's TCP and IPv4 option
// handling than a plain listener would. Pin the default off at build time
// rather than leaving it to whatever GODEBUG the runtime environment carries.
//
// See https://go.dev/doc/godebug#go-124. The behavioural half of this guard
// lives in server/mptcp_test.go.
const wantMultipathTCP = "0"

// TestGoModDisablesMultipathTCP guards the build wiring. The GODEBUG default is
// compiled in from the main module's go.mod, so dropping the directive turns
// MPTCP listeners back on for every build without any other visible change.
func TestGoModDisablesMultipathTCP(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	m := regexp.MustCompile(`(?m)multipathtcp\s*=\s*"?([0-3])"?`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("go.mod does not set godebug multipathtcp=%s, so Linux listeners default to MPTCP", wantMultipathTCP)
	}
	if got := string(m[1]); got != wantMultipathTCP {
		t.Fatalf("go.mod sets godebug multipathtcp=%s, want %s", got, wantMultipathTCP)
	}
}
