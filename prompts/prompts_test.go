package prompts

import (
	"strings"
	"testing"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

func TestParseConvergedAnswer_Accepted(t *testing.T) {
	raw := `DECISION: ACCEPTED
SEVERITY: HIGH
RATIONALE: The evidence shows an AWS access key with prefix AKIAI matching the active-credential pattern, located in apps/billing-service/config/prod.env, a production configuration file. No fixture markers, comments, or test-package context. This credential could be used directly by an attacker.
REVISED_DESCRIPTION: AWS access key exposed in production config file apps/billing-service/config/prod.env line 9. Rotate the IAM key and audit usage logs for unauthorized access.`

	r := ParseConvergedAnswer(raw)
	if !r.Accepted {
		t.Fatalf("expected Accepted=true; got %v", r.Accepted)
	}
	if r.Severity != findings.SeverityHigh {
		t.Errorf("severity: got %s want HIGH", r.Severity)
	}
	if !strings.Contains(r.Rationale, "AKIAI") {
		t.Errorf("rationale missing AKIAI citation; got: %s", r.Rationale)
	}
	if !strings.Contains(r.Description, "Rotate the IAM key") {
		t.Errorf("description missing rotation guidance; got: %s", r.Description)
	}
}

func TestParseConvergedAnswer_RejectedFixture(t *testing.T) {
	raw := `DECISION: REJECTED
SEVERITY: INFO
RATIONALE: The file path apps/billing-service/crypto_test/testkey.go is inside a _test package, and the key is bound to a variable named TestOnlyDoNotUse. This is clearly a test fixture, not a real credential. Production code does not consume from _test packages.
REVISED_DESCRIPTION: Test fixture in crypto_test package — not a real credential. Filter from future scans by adding _test/ to the ignore list.`

	r := ParseConvergedAnswer(raw)
	if r.Accepted {
		t.Fatalf("expected Accepted=false for fixture; got %v", r.Accepted)
	}
	if r.Severity != findings.SeverityInfo {
		t.Errorf("severity: got %s want INFO", r.Severity)
	}
	if !strings.Contains(r.Rationale, "test fixture") &&
		!strings.Contains(r.Rationale, "_test package") {
		t.Errorf("rationale missing fixture reasoning; got: %s", r.Rationale)
	}
}

func TestParseConvergedAnswer_CaseInsensitiveLabels(t *testing.T) {
	raw := `decision: accepted
Severity: CRITICAL
Rationale: Two dormant access keys, last used 25 months ago.
revised_description: sa-old-migration has two dormant Active IAM keys.`

	r := ParseConvergedAnswer(raw)
	if !r.Accepted {
		t.Error("expected Accepted=true for lowercase decision label")
	}
	if r.Severity != findings.SeverityCritical {
		t.Errorf("severity: got %s want CRITICAL", r.Severity)
	}
}

func TestParseConvergedAnswer_MultiLineRationale(t *testing.T) {
	raw := `DECISION: ACCEPTED
SEVERITY: HIGH
RATIONALE: The OAuth client 0oa1stale8FIXTUREabc has not been used in 1016 days.
The status field still reads ACTIVE, meaning the credential is live and
could be exchanged for an access token by anyone who learns the client_id
and secret.
REVISED_DESCRIPTION: Stale OAuth client (1016 days idle) should be revoked.`

	r := ParseConvergedAnswer(raw)
	if !r.Accepted {
		t.Fatal("expected Accepted=true")
	}
	if !strings.Contains(r.Rationale, "1016 days") {
		t.Errorf("rationale truncated; got: %s", r.Rationale)
	}
	if !strings.Contains(r.Rationale, "client_id and secret") {
		t.Errorf("rationale missed multi-line continuation; got: %s", r.Rationale)
	}
}

func TestParseConvergedAnswer_Unparseable(t *testing.T) {
	// Pure prose with no structured labels — should reject and surface
	// the truncated raw as the rationale.
	raw := "I'm not sure about this one. The evidence is a bit thin but it could be real, or it could be a fixture. I don't know."

	r := ParseConvergedAnswer(raw)
	if r.Accepted {
		t.Error("expected Accepted=false for unparseable output")
	}
	if !strings.Contains(r.Rationale, "unparseable") {
		t.Errorf("rationale should call out unparseable; got: %s", r.Rationale)
	}
}

func TestParseConvergedAnswer_PartialUnparseable(t *testing.T) {
	// Has labels but the structured-output check should still produce
	// usable values for what's there.
	raw := `DECISION: REJECTED
RATIONALE: The location looks like a fixture.`

	r := ParseConvergedAnswer(raw)
	if r.Accepted {
		t.Error("expected Accepted=false")
	}
	// SEVERITY missing — should fall through to MEDIUM default.
	if r.Severity != findings.SeverityMedium {
		t.Errorf("severity default: got %s want MEDIUM", r.Severity)
	}
	if r.Rationale == "" {
		t.Error("rationale should be populated from what was parseable")
	}
}

func TestFormatCandidate_IncludesAllSections(t *testing.T) {
	c := findings.Finding{
		ID:          "stale-oauth-0oa1stale8",
		Category:    findings.CategoryStaleOAuth,
		Severity:    findings.SeverityHigh,
		ScannerID:   "oauth",
		Title:       "OAuth client 0oa1stale8 unused for 1016 days",
		Description: "Client last used 2023-08-01; still active.",
		Evidence: []findings.Evidence{
			{
				Kind:        "api_field",
				Description: "Okta /api/v1/apps last_used",
				Location:    "okta:apps/0oa1stale8.lastUsed",
				Snippet:     "2023-08-01T14:22:00Z",
			},
		},
	}
	q := FormatCandidate(c)

	for _, want := range []string{
		"Candidate finding",
		"Evidence",
		"Judgment criteria",
		"Required output format",
		"DECISION: <ACCEPTED|REJECTED>",
		"0oa1stale8",
		"2023-08-01T14:22:00Z",
		"365 days",  // the staleness criteria text
	} {
		if !strings.Contains(q, want) {
			t.Errorf("formatted candidate missing %q", want)
		}
	}
}
