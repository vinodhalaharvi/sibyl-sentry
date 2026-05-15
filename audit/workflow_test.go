//go:build sibyl_stub

// Reproduction test for the [TMPRL1100] duplicate command panic
// from the audit workflow's emit-activity calls.
package audit

import (
	"context"
	"testing"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
)

// fakeConvergeWorkflow stands in for sibylproxy.ConvergeWorkflow during
// the test. By default accepts; failOdds is a 1-in-N probability of
// returning an error, exercising the err path.
func fakeConvergeWorkflowSucceeds(ctx workflow.Context, q sibylproxy.Question) (sibylproxy.Answer, error) {
	canned := "DECISION: ACCEPTED\nSEVERITY: HIGH\nRATIONALE: Test\nREVISED_DESCRIPTION: Test"
	return sibylproxy.Answer{Text: canned, Rounds: 1, Converged: true}, nil
}

// fakeConvergeWorkflowFails returns an error every time — exercises
// the err-path emit at workflow.go:361.
func fakeConvergeWorkflowFails(ctx workflow.Context, q sibylproxy.Question) (sibylproxy.Answer, error) {
	return sibylproxy.Answer{}, errFailStub
}

var errFailStub = stubErr("simulated child workflow failure")

type stubErr string

func (e stubErr) Error() string { return string(e) }

// fakeConvergeEmit records emit calls for assertion.
func fakeConvergeEmit(ctx context.Context, in ConvergeEmitInput) error {
	return nil
}

func TestRunConvergence_MultipleCandidates(t *testing.T) {
	// Build a fake set of 7 candidates — enough to trigger the
	// duplicate-command panic if it's still there.
	candidates := []findings.Finding{
		{ID: "c1", Title: "Cand 1", ScannerID: "secrets"},
		{ID: "c2", Title: "Cand 2", ScannerID: "secrets"},
		{ID: "c3", Title: "Cand 3", ScannerID: "secrets"},
		{ID: "c4", Title: "Cand 4", ScannerID: "oauth"},
		{ID: "c5", Title: "Cand 5", ScannerID: "scopes"},
		{ID: "c6", Title: "Cand 6", ScannerID: "dormancy"},
		{ID: "c7", Title: "Cand 7", ScannerID: "dormancy"},
	}

	// Wrap runConvergence in a workflow so we can run it via testsuite.
	type res struct {
		Accepted int
		Rejected int
	}
	wf := func(ctx workflow.Context) (res, error) {
		accepted, rejected := runConvergence(ctx, candidates)
		return res{len(accepted), len(rejected)}, nil
	}

	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	env.RegisterWorkflowWithOptions(fakeConvergeWorkflowSucceeds, workflow.RegisterOptions{
		Name: sibylproxy.ConvergeWorkflowName,
	})
	env.RegisterActivityWithOptions(fakeConvergeEmit, activity.RegisterOptions{Name: "ConvergeEmitActivity"})
	env.RegisterWorkflow(wf)

	env.SetWorkflowRunTimeout(2 * time.Minute)
	env.ExecuteWorkflow(wf)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow returned error: %v", err)
	}
	t.Log("workflow completed without panic — fix verified")
}

// TestRunConvergence_ChildFails exercises the err-path emit at line 361,
// which is what panicked in the real Temporal run.
func TestRunConvergence_ChildFails(t *testing.T) {
	candidates := []findings.Finding{
		{ID: "c1", Title: "Cand 1", ScannerID: "secrets"},
		{ID: "c2", Title: "Cand 2", ScannerID: "secrets"},
		{ID: "c3", Title: "Cand 3", ScannerID: "secrets"},
		{ID: "c4", Title: "Cand 4", ScannerID: "secrets"},
		{ID: "c5", Title: "Cand 5", ScannerID: "secrets"},
	}

	wf := func(ctx workflow.Context) (int, error) {
		accepted, rejected := runConvergence(ctx, candidates)
		return len(accepted) + len(rejected), nil
	}

	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterWorkflowWithOptions(fakeConvergeWorkflowFails, workflow.RegisterOptions{
		Name: sibylproxy.ConvergeWorkflowName,
	})
	env.RegisterActivityWithOptions(fakeConvergeEmit, activity.RegisterOptions{Name: "ConvergeEmitActivity"})
	env.RegisterWorkflow(wf)
	env.SetWorkflowRunTimeout(2 * time.Minute)
	env.ExecuteWorkflow(wf)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow returned error: %v", err)
	}
	t.Log("workflow handled failing children without panic")
}
