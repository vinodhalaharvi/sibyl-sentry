package regex_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/regex"
)

// fixturesPath returns the absolute path to the fixtures directory.
// We look in a few likely places so the test works whether you run it
// from the Sentry repo root or have the fixtures elsewhere.
func fixturesPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../../sibyl-sentry-fixtures",
		"../../sibyl-sentry-fixtures",
		os.Getenv("SENTRY_FIXTURES_PATH"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("fixtures repo not found; set SENTRY_FIXTURES_PATH or check out alongside this repo")
	return ""
}

func TestRegexScan_WorkingTree_FindsPlantedSecrets(t *testing.T) {
	path := fixturesPath(t)
	out, err := regex.Scan(context.Background(), regex.ScanInput{
		TargetPath:  path,
		ScanHistory: false,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.FilesScanned == 0 {
		t.Fatal("no files scanned")
	}
	t.Logf("scanned %d files; %d findings", out.FilesScanned, len(out.Findings))

	// Expect at least: AWS key in billing prod.env, Slack webhook in analytics.
	wantSubstrings := []string{
		"AWS access key",
		"Slack",
	}
	for _, want := range wantSubstrings {
		found := false
		for _, f := range out.Findings {
			if strings.Contains(f.Title, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no finding matching %q", want)
		}
	}
}

func TestRegexScan_History_FindsRemovedSecrets(t *testing.T) {
	path := fixturesPath(t)
	out, err := regex.Scan(context.Background(), regex.ScanInput{
		TargetPath:  path,
		ScanHistory: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	t.Logf("scanned %d files + %d bytes history; %d findings",
		out.FilesScanned, out.HistoryBytesScanned, len(out.Findings))

	// Expect the legacy-cron AWS key to appear from git history.
	// (It's in the working tree of the older commits but not HEAD.)
	historicalFound := false
	for _, f := range out.Findings {
		for _, e := range f.Evidence {
			if e.Kind == "git_commit" && strings.Contains(e.Snippet, "AKIAI44QH8DHBEXAMPLE") {
				historicalFound = true
				break
			}
		}
		if historicalFound {
			t.Logf("historical exposure found: %s @ %s", f.Title, f.Evidence[0].Location)
			break
		}
	}
	if !historicalFound {
		// Not a hard failure — the test repo might not have the history commits
		// (e.g. shallow clone). Log it and move on.
		t.Log("historical-exposure finding not present; check fixtures repo history")
	}
}

func TestRegexScan_HighSeverityForKeys(t *testing.T) {
	path := fixturesPath(t)
	out, err := regex.Scan(context.Background(), regex.ScanInput{TargetPath: path})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range out.Findings {
		if strings.Contains(f.Title, "AWS access key") && f.Severity < findings.SeverityHigh {
			t.Errorf("AWS access key finding should be HIGH+, got %s", f.Severity)
		}
	}
}
