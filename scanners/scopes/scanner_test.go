package scopes_test

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

	"github.com/vinodhalaharvi/sibyl-sentry/scanners/scopes"
)

var (
	mockBaseURL  string
	mockProcess  *exec.Cmd
	fixturesRoot string
)

func TestMain(m *testing.M) {
	fixturesRoot = findFixturesRoot()
	if fixturesRoot == "" {
		fmt.Fprintln(os.Stderr, "skipping scopes scanner tests: fixtures not found")
		os.Exit(0)
	}
	mockBin := filepath.Join(fixturesRoot, "bin", "mock-okta")
	if _, err := os.Stat(mockBin); err != nil {
		fmt.Fprintf(os.Stderr, "skipping scopes tests: %s not built\n", mockBin)
		os.Exit(0)
	}
	port, _ := freePort()
	mockBaseURL = fmt.Sprintf("http://localhost:%d", port)

	mockProcess = exec.Command(mockBin,
		"-addr", fmt.Sprintf(":%d", port),
		"-data", filepath.Join(fixturesRoot, "data", "okta"),
	)
	mockProcess.Stderr = os.Stderr
	if err := mockProcess.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start mock-okta: %v\n", err)
		os.Exit(1)
	}
	if !waitReady(mockBaseURL+"/healthz", 5*time.Second) {
		_ = mockProcess.Process.Kill()
		os.Exit(1)
	}
	code := m.Run()
	_ = mockProcess.Process.Kill()
	_ = mockProcess.Wait()
	os.Exit(code)
}

func TestScanOverPrivilege_FindsReportingDashboard(t *testing.T) {
	out, err := scopes.ScanOverPrivilege(context.Background(), scopes.ScanInput{
		OktaBaseURL: mockBaseURL,
		OktaToken:   "test",
	})
	if err != nil {
		t.Fatalf("ScanOverPrivilege: %v", err)
	}
	t.Logf("reviewed %d clients; %d findings", out.ClientsReviewed, len(out.Findings))

	// The Reporting Dashboard client (0oa4overpriv2) has 7 granted scopes
	// and only used 2 in the lookback window — must be flagged.
	var found bool
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "0oa4overpriv2FIXTUREabc") {
			found = true
			// The Critic should reject any finding without specific unused
			// scope names. We can spot-check that the evidence carries them.
			var saw bool
			for _, e := range f.Evidence {
				if e.Kind == "computed" && strings.Contains(e.Snippet, "okta.users.manage") {
					saw = true
				}
			}
			if !saw {
				t.Errorf("finding for 0oa4overpriv2 missing specific unused-scope evidence; got: %s", f.Description)
			}
		}
	}
	if !found {
		t.Error("over-privileged client 0oa4overpriv2FIXTUREabc not flagged")
	}
}

func TestScanOverPrivilege_DoesNotFlagHealthy(t *testing.T) {
	out, err := scopes.ScanOverPrivilege(context.Background(), scopes.ScanInput{
		OktaBaseURL: mockBaseURL,
		OktaToken:   "test",
	})
	if err != nil {
		t.Fatalf("ScanOverPrivilege: %v", err)
	}
	// The healthy client (0oa5healthy0) has 1 granted, 1 used.
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "0oa5healthy0FIXTUREabc") {
			t.Errorf("healthy client should NOT be flagged; got: %s", f.Title)
		}
	}
}

// --- helpers (duplicated across test files; small enough to not pull
// into a test-only shared package) ---

func findFixturesRoot() string {
	if env := os.Getenv("SENTRY_FIXTURES_PATH"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	for _, c := range []string{"../../../sibyl-sentry-fixtures", "../../sibyl-sentry-fixtures"} {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return ""
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

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
