package dormancy_test

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

	"github.com/vinodhalaharvi/sibyl-sentry/scanners/dormancy"
)

var (
	mockBaseURL  string
	mockProcess  *exec.Cmd
	fixturesRoot string
)

func TestMain(m *testing.M) {
	fixturesRoot = findFixturesRoot()
	if fixturesRoot == "" {
		fmt.Fprintln(os.Stderr, "skipping dormancy scanner tests: fixtures not found")
		os.Exit(0)
	}
	mockBin := filepath.Join(fixturesRoot, "bin", "mock-aws")
	if _, err := os.Stat(mockBin); err != nil {
		fmt.Fprintf(os.Stderr, "skipping dormancy tests: %s not built\n", mockBin)
		os.Exit(0)
	}
	port, _ := freePort()
	mockBaseURL = fmt.Sprintf("http://localhost:%d", port)

	mockProcess = exec.Command(mockBin,
		"-addr", fmt.Sprintf(":%d", port),
		"-data", filepath.Join(fixturesRoot, "data", "aws"),
	)
	mockProcess.Stderr = os.Stderr
	if err := mockProcess.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start mock-aws: %v\n", err)
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

func TestScanIAM_FindsDormantUsers(t *testing.T) {
	out, err := dormancy.ScanIAM(context.Background(), dormancy.ScanInput{
		AWSBaseURL: mockBaseURL,
		AWSToken:   "test",
	})
	if err != nil {
		t.Fatalf("ScanIAM: %v", err)
	}
	t.Logf("reviewed %d users, %d keys; %d findings", out.UsersReviewed, out.KeysReviewed, len(out.Findings))

	// Expect both dormant fixtures to be flagged:
	//   sa-old-migration   (25 months idle, 2 keys)
	//   sa-deprecated-etl  (41 months idle, 1 key)
	want := []string{"sa-old-migration", "sa-deprecated-etl"}
	for _, w := range want {
		var found bool
		for _, f := range out.Findings {
			if strings.Contains(f.Title, w) {
				found = true
				t.Logf("flagged: %s (%s)", w, f.Severity)
			}
		}
		if !found {
			t.Errorf("dormant user %q not flagged", w)
		}
	}
}

func TestScanIAM_DoesNotFlagHealthy(t *testing.T) {
	out, err := dormancy.ScanIAM(context.Background(), dormancy.ScanInput{
		AWSBaseURL: mockBaseURL,
		AWSToken:   "test",
	})
	if err != nil {
		t.Fatalf("ScanIAM: %v", err)
	}
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "sa-billing-prod") ||
			strings.Contains(f.Title, "sa-rotation-test") {
			t.Errorf("healthy user should NOT be flagged; got: %s", f.Title)
		}
	}
}

// --- helpers ---

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
