package oauth_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
)

func inventoryPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../../sibyl-sentry-fixtures/config/oauth-clients.json",
		"../../sibyl-sentry-fixtures/config/oauth-clients.json",
	}
	if env := os.Getenv("SENTRY_FIXTURES_PATH"); env != "" {
		candidates = append([]string{filepath.Join(env, "config/oauth-clients.json")}, candidates...)
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("oauth-clients.json fixture not found")
	return ""
}

func TestScanStale_FindsLegacyReportingTool(t *testing.T) {
	path := inventoryPath(t)
	out, err := oauth.ScanStale(context.Background(), oauth.ScanInput{
		InventoryPath: path,
	})
	if err != nil {
		t.Fatalf("ScanStale: %v", err)
	}
	if out.ClientsReviewed == 0 {
		t.Fatal("no clients reviewed")
	}
	t.Logf("reviewed %d clients; %d findings", out.ClientsReviewed, len(out.Findings))

	// We expect the stale client 0oa1stale8FIXTUREabc to be flagged.
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
	path := inventoryPath(t)
	out, err := oauth.ScanStale(context.Background(), oauth.ScanInput{
		InventoryPath: path,
	})
	if err != nil {
		t.Fatalf("ScanStale: %v", err)
	}
	// 0oa3ambig5FIXTUREabc last used 65 days ago — below the 365-day threshold.
	// The threshold-based scanner should not flag this; the Critic ought to
	// confirm by demanding strong staleness evidence.
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "0oa3ambig5FIXTUREabc") {
			t.Errorf("ambiguous client should NOT be flagged at default threshold; got: %s", f.Title)
		}
	}
}
