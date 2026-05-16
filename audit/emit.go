// Package audit: convergence event emission helper.
//
// Workflow code in Temporal must remain deterministic — no side effects.
// To publish broker events as the audit progresses through Phase 2 (per-
// candidate convergence), the workflow schedules tiny activities whose
// only job is to publish one event each.
//
// The activity runs in the worker process where the broker is registered
// globally, so the published event reaches any SSE subscriber listening
// on the parent audit's workflow ID.
package audit

import (
	"context"
	"time"

	"go.temporal.io/sdk/activity"

	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
)

// ConvergeEmitInput carries the data needed to construct one event.
//
// Kind is one of:
//   "node.started"   — a ConvergeWorkflow child has been spawned
//   "node.completed" — a child completed (accepted by Critic)
//   "node.failed"    — a child failed or was rejected by Critic
type ConvergeEmitInput struct {
	ParentWorkflowID     string
	Kind                 string
	CandidateID          string
	CandidateTitle       string
	CandidateDescription string
	ChildWorkflowID      string
	Severity             string
	Rounds               int
	Accepted             bool
	Reason               string
	Rationale            string
	DurationMs           int64
}

// ConvergeEmitActivity publishes one event to the global broker.
// Always tagged with ParentWorkflowID so SSE subscribers on the parent
// audit receive it. NodeID is the candidate ID, Label is human-readable.
func ConvergeEmitActivity(ctx context.Context, in ConvergeEmitInput) error {
	emitter := sibylproxy.EmitterForActivity(ctx)
	if emitter == nil {
		return nil
	}
	// Force the parent workflow ID so the event is routed to the audit's
	// SSE subscriber, not this emit activity's parent workflow.
	wid := in.ParentWorkflowID

	label := in.CandidateTitle
	if len(label) > 80 {
		label = label[:77] + "..."
	}

	switch in.Kind {
	case "node.started":
		ev := sibylproxy.NewNodeStarted(wid, "converge:"+in.CandidateID, label)
		emitter.Emit(ev)
	case "node.completed":
		output := map[string]interface{}{
			"converge_workflow_id": in.ChildWorkflowID,
			"candidate_id":         in.CandidateID,
			"severity":             in.Severity,
			"rounds":               in.Rounds,
			"accepted":             in.Accepted,
			"rationale":            in.Rationale,
			"description":          in.CandidateDescription,
		}
		ev := sibylproxy.NewNodeCompleted(wid, "converge:"+in.CandidateID, label,
			output, time.Duration(in.DurationMs)*time.Millisecond)
		emitter.Emit(ev)
	case "node.failed":
		// Reuse NodeFailed for both Critic rejection and workflow error.
		errStr := in.Reason
		if errStr == "" {
			errStr = "rejected by Critic"
		}
		ev := sibylproxy.NewNodeFailed(wid, "converge:"+in.CandidateID, label,
			emitterErr(errStr), time.Duration(in.DurationMs)*time.Millisecond)
		emitter.Emit(ev)
	}

	// Activity heartbeat for very long-running audits — keeps Temporal happy.
	activity.RecordHeartbeat(ctx, "emit done")
	return nil
}

// emitterErr is a tiny error wrapper since NewNodeFailed expects an error.
type emitterErr string

func (e emitterErr) Error() string { return string(e) }

// ---------------------------------------------------------------------------
// Verdict emit — publishes broker events for the "Awaiting Verdicts" tile.
// ---------------------------------------------------------------------------

// VerdictEmitInput carries the data needed to publish one verdict-tile event.
//
// Kind is one of:
//
//	"verdicts.started"   — the workflow has begun the wait phase
//	"verdicts.completed" — the wait phase finished, with counts in Output
//
// NodeID for the tile is always "verdicts:summary" (single tile per audit).
type VerdictEmitInput struct {
	ParentWorkflowID string
	Kind             string
	TotalFindings    int
	TimeoutSeconds   int   // populated on "verdicts.started"
	WithVerdict      int   // populated on "verdicts.completed"
	TimedOut         int   // populated on "verdicts.completed"
	Errored          int   // populated on "verdicts.completed"
	DurationMs       int64 // populated on "verdicts.completed"
}

// VerdictEmitActivity publishes one verdict-tile event to the global broker.
// Mirrors ConvergeEmitActivity in structure: the activity runs in the worker
// process where the broker is registered, so SSE subscribers on the parent
// audit's workflow ID receive the event.
func VerdictEmitActivity(ctx context.Context, in VerdictEmitInput) error {
	emitter := sibylproxy.EmitterForActivity(ctx)
	if emitter == nil {
		return nil
	}
	wid := in.ParentWorkflowID
	const nodeID = "verdicts:summary"

	switch in.Kind {
	case "verdicts.started":
		label := "Awaiting human verdicts"
		ev := sibylproxy.NewNodeStarted(wid, nodeID, label)
		emitter.Emit(ev)
	case "verdicts.completed":
		label := "Verdict collection complete"
		output := map[string]interface{}{
			"total_findings": in.TotalFindings,
			"with_verdict":   in.WithVerdict,
			"timed_out":      in.TimedOut,
			"errored":        in.Errored,
		}
		ev := sibylproxy.NewNodeCompleted(wid, nodeID, label,
			output, time.Duration(in.DurationMs)*time.Millisecond)
		emitter.Emit(ev)
	}

	activity.RecordHeartbeat(ctx, "verdict emit done")
	return nil
}
