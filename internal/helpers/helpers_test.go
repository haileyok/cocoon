package helpers

import (
	"strings"
	"testing"
)

func TestRandomVarchar(t *testing.T) {
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	for _, n := range []int{1, 5, 6, 24, 64} {
		got := RandomVarchar(n)
		if len(got) != n {
			t.Fatalf("RandomVarchar(%d) length = %d", n, len(got))
		}
		for _, r := range got {
			if !strings.ContainsRune(allowed, r) {
				t.Fatalf("RandomVarchar(%d) produced %q outside the allowed alphabet", n, r)
			}
		}
	}

	// Two independent 24-char draws colliding would indicate a broken generator.
	if RandomVarchar(24) == RandomVarchar(24) {
		t.Fatal("two 24-char codes were identical")
	}
}
