package server

import (
	"testing"

	"github.com/haileyok/cocoon/oauth/dpop"
)

func TestDpopJktMatches(t *testing.T) {
	jkt := "thumbprint-abc"
	other := jkt

	tests := []struct {
		name     string
		tokenJkt *string
		proof    *dpop.Proof
		want     bool
	}{
		{"not bound, no proof", nil, nil, true},
		{"not bound, proof present", nil, &dpop.Proof{JKT: jkt}, true},
		{"bound, missing proof", &jkt, nil, false},
		{"bound, matching proof", &jkt, &dpop.Proof{JKT: other}, true},
		{"bound, mismatched proof", &jkt, &dpop.Proof{JKT: "different"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dpopJktMatches(tt.tokenJkt, tt.proof); got != tt.want {
				t.Fatalf("dpopJktMatches = %v, want %v", got, tt.want)
			}
		})
	}
}
