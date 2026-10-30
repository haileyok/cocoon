package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestListenersAreNotMultipathTCP exercises the go.mod godebug default instead
// of its text. The listener is created by this test binary, which is built from
// the same main module as the server, so it inherits the defaults a deployed
// cocoon binds with: if they stop disabling MPTCP the listener starts answering
// MP_CAPABLE and this fails.
func TestListenersAreNotMultipathTCP(t *testing.T) {
	requireLinux(t)

	// An explicit GODEBUG value wins over the go.mod default, so a host that
	// sets multipathtcp itself invalidates the assumption under test.
	if v := godebugSetting("multipathtcp"); v != "" && v != "0" {
		t.Skipf("GODEBUG sets multipathtcp=%s, which overrides the go.mod default", v)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	if negotiatedMPTCP(t, ln) {
		t.Fatal("listener negotiated MPTCP, but cocoon should only speak plain TCP")
	}
}

// TestServeListenerIgnoresMultipathTCPGODEBUG covers the case the go.mod
// directive cannot: an environment that sets multipathtcp itself.
// serveListener opts the socket out directly, which no GODEBUG value can
// override. GODEBUG is read once at startup, so the override only exists in a
// child process.
func TestServeListenerIgnoresMultipathTCPGODEBUG(t *testing.T) {
	requireLinux(t)

	if os.Getenv("COCOON_MPTCP_SUBPROCESS") == "1" {
		ln, err := serveListener(context.Background(), "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close() //nolint:errcheck // test cleanup

		if negotiatedMPTCP(t, ln) {
			t.Fatal("serveListener negotiated MPTCP despite GODEBUG=multipathtcp=2")
		}

		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestServeListenerIgnoresMultipathTCPGODEBUG$")
	cmd.Env = append(withoutEnv(os.Environ(), "GODEBUG"),
		"COCOON_MPTCP_SUBPROCESS=1",
		"GODEBUG=multipathtcp=2",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
}

// TestServeListenerServesHTTP covers the refactor away from ListenAndServe: the
// server must still answer requests on the listener it was handed.
func TestServeListenerServesHTTP(t *testing.T) {
	ln, err := serveListener(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}

	go func() { _ = srv.Serve(ln) }()
	defer srv.Close() //nolint:errcheck // test cleanup

	resp, err := http.Get("http://" + ln.Addr().String() + "/xrpc/_health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// negotiatedMPTCP offers MPTCP to ln and reports whether it was accepted.
// SetMultipathTCP overrides the GODEBUG default for the dialer only, so the
// offer comes back only if the listener itself is an MPTCP socket.
func negotiatedMPTCP(t *testing.T, ln net.Listener) bool {
	t.Helper()

	var d net.Dialer
	d.SetMultipathTCP(true)

	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial %s: %v", ln.Addr(), err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup

	used, err := conn.(*net.TCPConn).MultipathTCP()
	if err != nil {
		// Kernels built without MPTCP, or with net.mptcp.enabled=0, cannot
		// report a state; the go.mod guard in the root package still covers
		// the wiring.
		t.Skipf("cannot query MPTCP state: %v", err)
	}

	return used
}

func requireLinux(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("MPTCP listeners are a Linux-only default")
	}
}

// godebugSetting returns the value of key from the GODEBUG environment
// variable, or "" when it is unset.
func godebugSetting(key string) string {
	for _, kv := range strings.Split(os.Getenv("GODEBUG"), ",") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}

	return ""
}

// withoutEnv returns env with every entry for key removed.
func withoutEnv(env []string, key string) []string {
	out := make([]string, 0, len(env))

	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && k == key {
			continue
		}

		out = append(out, kv)
	}

	return out
}
