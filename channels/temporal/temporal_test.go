package temporal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tsdkactivity "go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	tsdkworkflow "go.temporal.io/sdk/workflow"

	"github.com/vinodhalaharvi/sibyl-sentry/channels"
)

// ---------------------------------------------------------------------------
// Helpers: build a minimal Dispatcher whose channel records what was posted
// and returns scripted verdicts/replies.
// ---------------------------------------------------------------------------

type scriptedAdapter struct {
	posted    []channels.Message
	verdict   channels.Verdict
	verdictOK bool
	replies   []channels.Reply
}

func (s *scriptedAdapter) channel(name string) channels.Channel {
	ch := channels.Channel{Name: name}
	ch.Notify = func(_ context.Context, m channels.Message) (channels.Receipt, error) {
		s.posted = append(s.posted, m)
		return channels.Receipt{
			Channel:  name,
			ID:       "msg-1",
			Target:   m.Target,
			PostedAt: time.Now(),
		}, nil
	}
	ch.Await = func(_ context.Context, _ channels.Receipt, _ channels.AwaitOpts) (channels.Verdict, error) {
		if !s.verdictOK {
			return channels.Verdict{}, channels.ErrTimeout
		}
		v := s.verdict
		if v.Channel == "" {
			v.Channel = name
		}
		return v, nil
	}
	ch.Converse = func(_ context.Context, _ channels.Receipt, _ channels.AwaitOpts) ([]channels.Reply, error) {
		return s.replies, nil
	}
	return ch
}

func newDispatcher(t *testing.T, adapter *scriptedAdapter) *channels.Dispatcher {
	t.Helper()
	d, err := channels.New(
		channels.WithRouter(channels.FixedRouter("scripted", "#test")),
		channels.WithChannel(adapter.channel("scripted")),
	)
	require.NoError(t, err)
	return d
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewActivities_RequiresDispatcher(t *testing.T) {
	_, err := NewActivities(nil)
	if err == nil {
		t.Error("expected error when dispatcher is nil")
	}
}

// ---------------------------------------------------------------------------
// Direct activity tests (no workflow harness — call the activity methods
// directly. This is the cheapest, fastest path.)
// ---------------------------------------------------------------------------

func TestPostActivity_Direct(t *testing.T) {
	adapter := &scriptedAdapter{}
	d := newDispatcher(t, adapter)
	acts, err := NewActivities(d)
	require.NoError(t, err)

	res, err := acts.Post(context.Background(), channels.Message{
		Title: "hello",
	})
	require.NoError(t, err)
	require.Len(t, res.Receipts, 1)
	require.Empty(t, res.Errors)
	require.Equal(t, "scripted", res.Receipts[0].Channel)
	require.Len(t, adapter.posted, 1)
}

func TestPostActivity_NoTargetReturnsError(t *testing.T) {
	adapter := &scriptedAdapter{}
	d, err := channels.New(
		// Severity router will drop INFO when threshold is HIGH → no destinations.
		channels.WithRouter(channels.SeverityRouter("scripted", "#x", channels.SeverityHigh, nil)),
		channels.WithChannel(adapter.channel("scripted")),
	)
	require.NoError(t, err)
	acts, err := NewActivities(d)
	require.NoError(t, err)

	_, err = acts.Post(context.Background(), channels.Message{Severity: channels.SeverityInfo})
	if !errors.Is(err, channels.ErrNoTarget) {
		t.Errorf("expected ErrNoTarget, got %v", err)
	}
}

func TestAwaitVerdictActivity_Direct(t *testing.T) {
	adapter := &scriptedAdapter{
		verdict:   channels.Verdict{Choice: "accept"},
		verdictOK: true,
	}
	d := newDispatcher(t, adapter)
	acts, err := NewActivities(d)
	require.NoError(t, err)

	// Post first to get receipts.
	pres, err := acts.Post(context.Background(), channels.Message{Title: "x"})
	require.NoError(t, err)

	v, err := acts.AwaitVerdict(context.Background(), pres.Receipts, channels.AwaitOpts{Timeout: time.Second})
	require.NoError(t, err)
	require.Equal(t, "accept", v.Choice)
	require.Equal(t, "scripted", v.Channel)
}

func TestAwaitRepliesActivity_Direct(t *testing.T) {
	adapter := &scriptedAdapter{
		replies: []channels.Reply{{Body: "ack"}},
	}
	d := newDispatcher(t, adapter)
	acts, err := NewActivities(d)
	require.NoError(t, err)

	pres, err := acts.Post(context.Background(), channels.Message{Title: "x"})
	require.NoError(t, err)

	replies, err := acts.AwaitReplies(context.Background(), pres.Receipts, channels.AwaitOpts{})
	require.NoError(t, err)
	require.Len(t, replies, 1)
	require.Equal(t, "ack", replies[0].Body)
}

// ---------------------------------------------------------------------------
// Workflow integration via Temporal testsuite
//
// These tests prove the activities are correctly invokable from a workflow
// using the workflow-side helpers (PostFromWorkflow, AwaitVerdictFromWorkflow).
// ---------------------------------------------------------------------------

// demoWorkflow exercises Post + AwaitVerdict end-to-end inside a workflow.
func demoWorkflow(ctx tsdkworkflow.Context) (channels.Verdict, error) {
	pres, err := PostFromWorkflow(ctx, channels.Message{
		Title:    "Stale OAuth client",
		Severity: channels.SeverityCritical,
	}, PostOptions{StartToCloseTimeout: time.Minute})
	if err != nil {
		return channels.Verdict{}, err
	}
	return AwaitVerdictFromWorkflow(ctx, pres.Receipts, channels.AwaitOpts{
		Timeout: 30 * time.Second,
	}, AwaitVerdictOptions{StartToCloseTimeout: time.Minute})
}

func TestWorkflow_PostThenAwaitVerdict(t *testing.T) {
	adapter := &scriptedAdapter{
		verdict:   channels.Verdict{Choice: "accept", Actor: channels.Identity{Canonical: "slack:U1"}},
		verdictOK: true,
	}
	d := newDispatcher(t, adapter)
	acts, err := NewActivities(d)
	require.NoError(t, err)

	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(acts.Post, tsdkactivity.RegisterOptions{Name: ActivityPost})
	env.RegisterActivityWithOptions(acts.AwaitVerdict, tsdkactivity.RegisterOptions{Name: ActivityAwaitVerdict})

	env.ExecuteWorkflow(demoWorkflow)

	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())

	var v channels.Verdict
	require.NoError(t, env.GetWorkflowResult(&v))
	require.Equal(t, "accept", v.Choice)
	require.Equal(t, "slack:U1", v.Actor.Canonical)
	require.Len(t, adapter.posted, 1)
	require.Equal(t, "Stale OAuth client", adapter.posted[0].Title)
}

func TestWorkflow_AwaitVerdictTimesOut(t *testing.T) {
	adapter := &scriptedAdapter{verdictOK: false} // adapter always returns ErrTimeout
	d := newDispatcher(t, adapter)
	acts, err := NewActivities(d)
	require.NoError(t, err)

	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(acts.Post, tsdkactivity.RegisterOptions{Name: ActivityPost})
	env.RegisterActivityWithOptions(acts.AwaitVerdict, tsdkactivity.RegisterOptions{Name: ActivityAwaitVerdict})

	env.ExecuteWorkflow(demoWorkflow)

	require.True(t, env.IsWorkflowCompleted())
	err = env.GetWorkflowError()
	require.Error(t, err)
	// The error wraps channels.ErrTimeout; the workflow harness wraps further,
	// but the underlying message must mention "timed out".
	require.Contains(t, err.Error(), "timed out")
}
