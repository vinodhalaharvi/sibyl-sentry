package oauth_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
)

// Tests run against a real mock-okta server started by TestMain.
//
// To run these tests you need:
//  1. The sibyl-sentry-fixtures repo cloned alongside this repo (or set
//     SENTRY_FIXTURES_PATH).
//  2. Its mock-okta binary built (run `make build` in the fixtures repo).
//
// If either is missing, the tests skip with a clear message.

var (
	mockBaseURL  string
	mockProcess  *exec.Cmd
	fixturesRoot string
)

func TestMain(m *testing.M) {
	// Find fixtures repo.
	fixturesRoot = findFixturesRoot()
	if fixturesRoot == "" {
		// Can't find them — skip everything.
		fmt.Fprintln(os.Stderr, "skipping oauth scanner tests: sibyl-sentry-fixtures not found")
		os.Exit(0)
	}

	mockBin := filepath.Join(fixturesRoot, "bin", "mock-okta")
	if _, err := os.Stat(mockBin); err != nil {
		fmt.Fprintf(os.Stderr, "skipping oauth scanner tests: %s not built (run 'make build' in fixtures repo)\n", mockBin)
		os.Exit(0)
	}

	// Pick a free port to avoid clashing with any already-running mock.
	port, err := freePort()
	if err != nil {
		fmt.Fprintf(os.Stderr, "freePort: %v\n", err)
		os.Exit(1)
	}
	mockBaseURL = fmt.Sprintf("http://localhost:%d", port)

	dataDir := filepath.Join(fixturesRoot, "data", "okta")
	mockProcess = exec.Command(mockBin,
		"-addr", fmt.Sprintf(":%d", port),
		"-data", dataDir,
	)
	mockProcess.Stdout = nil
	mockProcess.Stderr = os.Stderr
	if err := mockProcess.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start mock-okta: %v\n", err)
		os.Exit(1)
	}

	// Wait for readiness.
	if !waitReady(mockBaseURL+"/healthz", 5*time.Second) {
		_ = mockProcess.Process.Kill()
		fmt.Fprintln(os.Stderr, "mock-okta did not become ready")
		os.Exit(1)
	}

	code := m.Run()

	if mockProcess != nil && mockProcess.Process != nil {
		_ = mockProcess.Process.Kill()
		_ = mockProcess.Wait()
	}
	os.Exit(code)
}

func TestScanStale_FindsLegacyReportingTool(t *testing.T) {
	out, err := oauth.ScanStale(context.Background(), oauth.ScanInput{
		OktaBaseURL: mockBaseURL,
		OktaToken:   "test",
	})
	if err != nil {
		t.Fatalf("ScanStale: %v", err)
	}
	if out.ClientsReviewed == 0 {
		t.Fatal("no clients reviewed")
	}
	t.Logf("reviewed %d clients; %d findings", out.ClientsReviewed, len(out.Findings))

	// Expect the stale client to be flagged.
	var found bool
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "0oa1stale8FIXTUREabc") {
			found = true
			t.Logf("flagged: %s (%s)", f.Title, f.Severity)
		}
	}
	if !found {
		t.Error("stale client 0oa1stale8FIXTUREabc not flagged")
	}
}

func TestScanStale_DoesNotFlagAmbiguous(t *testing.T) {
	out, err := oauth.ScanStale(context.Background(), oauth.ScanInput{
		OktaBaseURL: mockBaseURL,
		OktaToken:   "test",
	})
	if err != nil {
		t.Fatalf("ScanStale: %v", err)
	}
	// 0oa3ambig5 was last used 65 days ago — below the 365-day threshold.
	// The threshold-based scanner should not flag this; the Critic ought to
	// confirm by demanding strong staleness evidence.
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "0oa3ambig5FIXTUREabc") {
			t.Errorf("ambiguous client should NOT be flagged at default threshold; got: %s", f.Title)
		}
	}
}

func TestScanStale_BadAuthReturnsError(t *testing.T) {
	// Empty token → constructor returns error.
	_, err := oauth.ScanStale(context.Background(), oauth.ScanInput{
		OktaBaseURL: mockBaseURL,
		OktaToken:   "",
	})
	if err == nil {
		t.Fatal("expected error for empty token; got nil")
	}
}

func TestScanStale_BadURLReturnsError(t *testing.T) {
	_, err := oauth.ScanStale(context.Background(), oauth.ScanInput{
		OktaBaseURL: "http://localhost:1",
		OktaToken:   "test",
	})
	if err == nil {
		t.Fatal("expected error connecting to bogus URL; got nil")
	}
}

// --- helpers ---

// findFixturesRoot looks in likely locations relative to the test
// working directory, plus the env override.
func findFixturesRoot() string {
	if env := os.Getenv("SENTRY_FIXTURES_PATH"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	candidates := []string{
		"../../../sibyl-sentry-fixtures",
		"../../sibyl-sentry-fixtures",
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return ""
}

// freePort asks the kernel for an unused port.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// waitReady polls the healthz endpoint until it returns 200 or the
// timeout elapses.
func waitReady(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
