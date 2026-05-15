package owners_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/owners"
)

func ownersPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../sibyl-sentry-fixtures/sentry-config/owners.json",
		"../sibyl-sentry-fixtures/sentry-config/owners.json",
	}
	if env := os.Getenv("SENTRY_FIXTURES_PATH"); env != "" {
		candidates = append([]string{filepath.Join(env, "sentry-config/owners.json")}, candidates...)
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("owners.json fixture not found")
	return ""
}

func TestResolver_PathPrefix(t *testing.T) {
	r, err := owners.Load(ownersPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := findings.Finding{OwnerHint: "apps/billing-service/config/prod.env:9"}
	a := r.Resolve(f)
	if a.JiraProject != "BILL" {
		t.Errorf("billing finding routed to %q, want BILL", a.JiraProject)
	}
}

func TestResolver_EmailLookup(t *testing.T) {
	r, err := owners.Load(ownersPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := findings.Finding{OwnerHint: "alice@example.com"}
	a := r.Resolve(f)
	if a.JiraProject != "DATA" {
		t.Errorf("alice@ routed to %q, want DATA", a.JiraProject)
	}
}

func TestResolver_Fallback(t *testing.T) {
	r, err := owners.Load(ownersPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := findings.Finding{OwnerHint: "unknown/path/somewhere"}
	a := r.Resolve(f)
	if a.JiraProject != "SEC" {
		t.Errorf("unknown finding routed to %q, want SEC", a.JiraProject)
	}
}
