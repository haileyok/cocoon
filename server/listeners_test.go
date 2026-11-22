package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func TestParseListenAddr(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		wantNetwork string
		wantAddr    string
		wantErr     string
	}{
		{name: "tcp address", addr: ":8080", wantNetwork: "tcp", wantAddr: ":8080"},
		{name: "loopback tcp address", addr: "127.0.0.1:0", wantNetwork: "tcp", wantAddr: "127.0.0.1:0"},
		{name: "unix address", addr: "unix:/run/cocoon/cocoon.sock", wantNetwork: "unix", wantAddr: "/run/cocoon/cocoon.sock"},
		{name: "empty unix path", addr: "unix:", wantErr: "unix socket path must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, addr, err := parseListenAddr(tt.addr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseListenAddr(%q) error = %v, want %q", tt.addr, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseListenAddr(%q): %v", tt.addr, err)
			}
			if network != tt.wantNetwork || addr != tt.wantAddr {
				t.Fatalf("parseListenAddr(%q) = (%q, %q), want (%q, %q)", tt.addr, network, addr, tt.wantNetwork, tt.wantAddr)
			}
		})
	}
}

func TestServeListenerServesUnixHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cocoon.sock")

	ln, err := serveListener(context.Background(), "unix:"+path)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}

	go func() { _ = srv.Serve(ln) }()
	defer srv.Close() //nolint:errcheck // test cleanup

	resp, err := unixHTTPClient(path).Get("http://unix/xrpc/_health")
	if err != nil {
		t.Fatalf("get over unix socket: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestServeListenerReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cocoon.sock")

	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale socket: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket disappeared: %v", err)
	}

	ln, err := serveListener(context.Background(), "unix:"+path)
	if err != nil {
		t.Fatalf("listen after unclean shutdown: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup
}

func TestServeListenerRejectsLiveSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cocoon.sock")

	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	defer live.Close() //nolint:errcheck // test cleanup

	ln, err := serveListener(context.Background(), "unix:"+path)
	if err == nil {
		ln.Close() //nolint:errcheck // test cleanup
		t.Fatal("expected an error for a socket that is already in use")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("error = %q, want it to mention the socket is in use", err)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("live socket was unlinked: %v", err)
	}
	conn.Close() //nolint:errcheck // test cleanup
}

func TestServeListenerRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cocoon.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	ln, err := serveListener(context.Background(), "unix:"+path)
	if err == nil {
		ln.Close() //nolint:errcheck // test cleanup
		t.Fatal("expected an error for a regular file at the socket path")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("error = %q, want it to mention the non-socket path", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("existing file was removed: %v", err)
	}
}

func TestServeAddr(t *testing.T) {
	tests := []struct {
		name string
		unix bool
	}{
		{name: "tcp address"},
		{name: "unix address", unix: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := reserveTCPAddr(t)
			url := "http://" + addr + "/xrpc/_health"
			var client *http.Client

			if tt.unix {
				addr = "unix:" + filepath.Join(t.TempDir(), "cocoon.sock")
				client = unixHTTPClient(strings.TrimPrefix(addr, "unix:"))
				url = "http://unix/xrpc/_health"
			}

			s := newTestServer(t)
			s.echo = echo.New()
			s.httpd = &http.Server{Addr: addr, Handler: s.echo}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- s.Serve(ctx) }()

			waitForStatus(t, url, client)

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve returned an error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not shut down")
			}

			if tt.unix {
				if _, err := os.Lstat(strings.TrimPrefix(addr, "unix:")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("unix socket still exists after shutdown: %v", err)
				}
			}
		})
	}
}

func TestNewValidatesAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr string
	}{
		{name: "missing address", addr: "", wantErr: "addr must be set"},
		{name: "unix address without a path", addr: "unix:", wantErr: "unix socket path must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(&Args{Addr: tt.addr})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func unixHTTPClient(path string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
}

func reserveTCPAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp address: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}

	return addr
}

func waitForStatus(t *testing.T, url string, client *http.Client) {
	t.Helper()

	if client == nil {
		client = http.DefaultClient
	}

	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close() //nolint:errcheck // test cleanup
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s never became ready: %v", url, lastErr)
}
