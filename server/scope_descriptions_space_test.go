package server

import (
	"strings"
	"testing"
)

func TestDescribeSpaceScopes(t *testing.T) {
	got := describeScopes("atproto space:com.example.group?collection=* space:com.example.group?action=read_self&manage=update")
	var spaces, manage *scopePermission
	for i := range got {
		switch got[i].Title {
		case "Your private spaces":
			spaces = &got[i]
		case "Manage your private spaces":
			manage = &got[i]
		case "Other permissions":
			t.Fatalf("space scopes fell through to other permissions: %v", got[i].Raw)
		}
	}
	if spaces == nil || len(spaces.Raw) != 2 || !strings.Contains(spaces.Detail, "com.example.group") {
		t.Fatalf("%+v", got)
	}
	if manage == nil || !manage.Sensitive || len(manage.Raw) != 1 {
		t.Fatalf("%+v", got)
	}
}
