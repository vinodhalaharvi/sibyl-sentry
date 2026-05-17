package audit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vinodhalaharvi/sibyl/channels"
	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

func TestApplyVerdicts_AttachesVerdictToMatchingFinding(t *testing.T) {
	accepted := []findings.Finding{
		{ID: "f-1", Title: "Stale OAuth"},
		{ID: "f-2", Title: "Dormant IAM"},
	}
	at := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	verdicts := []VerdictResult{
		{FindingID: "f-1", Choice: "accept", Actor: "slack:U1", Channel: "slack", At: at},
	}

	out := applyVerdicts(accepted, verdicts)
	if out[0].HumanVerdict != "accept" {
		t.Errorf("f-1 HumanVerdict = %q, want accept", out[0].HumanVerdict)
	}
	if out[0].HumanActor != "slack:U1" {
		t.Errorf("f-1 HumanActor = %q, want slack:U1", out[0].HumanActor)
	}
	if !out[0].HumanVerdictAt.Equal(at) {
		t.Errorf("f-1 HumanVerdictAt = %v, want %v", out[0].HumanVerdictAt, at)
	}
	if out[0].HumanVerdictChannel != "slack" {
		t.Errorf("f-1 HumanVerdictChannel = %q, want slack", out[0].HumanVerdictChannel)
	}
	// f-2 has no verdict — must be untouched.
	if out[1].HumanVerdict != "" {
		t.Errorf("f-2 should have no verdict, got %q", out[1].HumanVerdict)
	}
}

func TestApplyVerdicts_EmptyVerdictsIsNoOp(t *testing.T) {
	accepted := []findings.Finding{{ID: "f-1", Title: "x"}}
	out := applyVerdicts(accepted, nil)
	if out[0].HumanVerdict != "" {
		t.Error("no verdicts should leave findings untouched")
	}
}

func TestApplyVerdicts_TimedOutVerdictsDoNotMutate(t *testing.T) {
	accepted := []findings.Finding{{ID: "f-1", Title: "x"}}
	verdicts := []VerdictResult{
		{FindingID: "f-1", Timeout: true}, // Choice is empty
	}
	out := applyVerdicts(accepted, verdicts)
	if out[0].HumanVerdict != "" {
		t.Errorf("timed-out verdict should not set HumanVerdict, got %q", out[0].HumanVerdict)
	}
}

func TestApplyVerdicts_UnknownFindingIDIsIgnored(t *testing.T) {
	accepted := []findings.Finding{{ID: "f-1"}}
	verdicts := []VerdictResult{
		{FindingID: "f-999", Choice: "accept"},
	}
	out := applyVerdicts(accepted, verdicts)
	if out[0].HumanVerdict != "" {
		t.Error("verdict for unknown finding ID should be ignored")
	}
}

func TestIsTimeout(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{channels.ErrTimeout, true},
		{errors.New("await timed out before quorum"), true},
		{errors.New("activity error: context deadline exceeded"), false},
		{errors.New("rate limited"), false},
		{errors.New("something timed out somewhere"), true},
	}
	for _, c := range cases {
		if got := isTimeout(c.err); got != c.want {
			t.Errorf("isTimeout(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestCountWithVerdict(t *testing.T) {
	vs := []VerdictResult{
		{Choice: "accept"},
		{Choice: ""},
		{Choice: "reject"},
		{Timeout: true},
	}
	if got := countWithVerdict(vs); got != 2 {
		t.Errorf("countWithVerdict = %d, want 2", got)
	}
}

func TestCountTimeouts(t *testing.T) {
	vs := []VerdictResult{
		{Timeout: true},
		{Choice: "accept"},
		{Timeout: true},
		{Error: "boom"},
	}
	if got := countTimeouts(vs); got != 2 {
		t.Errorf("countTimeouts = %d, want 2", got)
	}
}

func TestCountErrored(t *testing.T) {
	vs := []VerdictResult{
		{Error: "boom"},
		{Choice: "accept"},
		{Timeout: true},
		{Error: "rate limited"},
	}
	if got := countErrored(vs); got != 2 {
		t.Errorf("countErrored = %d, want 2", got)
	}
}

func TestFindingToMessage_PreservesEssentialFields(t *testing.T) {
	f := findings.Finding{
		ID:       "f-42",
		Title:    "Stale OAuth client",
		Severity: findings.SeverityCritical,
		Evidence: []findings.Evidence{
			{Kind: "api_field", Description: "lastUsed", Location: "2023-08-01"},
		},
	}
	ref := channels.WorkflowRef{
		WorkflowID: "wf-1",
		RunID:      "run-1",
		TraceURL:   "http://temporal.test/workflow/wf-1",
	}
	m := findingToMessage(f, ref)

	if m.Subject.Kind != "finding" || m.Subject.ID != "f-42" {
		t.Errorf("subject = %+v, want kind=finding id=f-42", m.Subject)
	}
	if m.Title != "Stale OAuth client" {
		t.Errorf("title = %q", m.Title)
	}
	if m.Severity != channels.SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL", m.Severity)
	}
	if len(m.Evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(m.Evidence))
	}
	if m.WorkflowRef.WorkflowID != "wf-1" {
		t.Errorf("workflow ref not propagated: %+v", m.WorkflowRef)
	}
	// All standard actions present.
	if len(m.Actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(m.Actions))
	}
	ids := []string{m.Actions[0].ID, m.Actions[1].ID, m.Actions[2].ID}
	want := []string{"accept", "reject", "snooze"}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("action[%d].ID = %q, want %q", i, ids[i], want[i])
		}
	}
}

func TestTemporalDeepLink(t *testing.T) {
	got := temporalDeepLink("http://localhost:8233", "wf-1", "run-1")
	if !strings.HasPrefix(got, "http://localhost:8233/") {
		t.Errorf("expected URL prefix, got %q", got)
	}
	if !strings.Contains(got, "wf-1") || !strings.Contains(got, "run-1") {
		t.Errorf("expected IDs in URL, got %q", got)
	}
	// Empty base = empty URL.
	if got := temporalDeepLink("", "x", "y"); got != "" {
		t.Errorf("empty base should produce empty URL, got %q", got)
	}
}
