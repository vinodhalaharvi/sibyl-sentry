package audit

import (
	"strconv"
	"strings"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/vinodhalaharvi/sibyl/channels"
	chtemporal "github.com/vinodhalaharvi/sibyl/channels/temporal"
	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

// PostFindingsResult records the per-finding outcome of channel posting.
// Mirrors the shape of TicketResult so the UI can surface both consistently.
type PostFindingsResult struct {
	FindingID string
	Posted    bool
	Channels  []string           // names of channels that received the post
	Receipts  []channels.Receipt // populated when Posted=true; needed for AwaitVerdict
	Error     string
}

// VerdictResult records the per-finding outcome of waiting for a human
// verdict via a channel (Slack reaction, email reply, etc.). One per finding
// for which a verdict was solicited.
type VerdictResult struct {
	FindingID string
	Choice    string    // "accept" | "reject" | "snooze" | "" if no verdict
	Actor     string    // resolved Identity.Canonical, e.g. "slack:U0123"
	Channel   string    // which channel produced the verdict
	At        time.Time // when the verdict was recorded
	Timeout   bool      // true if the await timed out before a verdict arrived
	Error     string    // non-empty on activity-level failure
}

// postFindings is Phase 3b: fan-out one channel.Post activity per accepted
// finding. Activities decide whether to actually post based on routing
// configuration (severity threshold, channel availability, etc.).
//
// This function is a no-op if channels are not configured at the worker level
// — the activity will return ErrNoTarget and we record that as a skip. The
// rest of the workflow proceeds normally. Channel integration is opt-in.
func postFindings(ctx workflow.Context, accepted []findings.Finding, traceURLBase string) []PostFindingsResult {
	postOpts := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2,
			MaximumAttempts:    2,
		},
	}
	pctx := workflow.WithActivityOptions(ctx, postOpts)

	wfInfo := workflow.GetInfo(ctx)
	workflowID := wfInfo.WorkflowExecution.ID
	runID := wfInfo.WorkflowExecution.RunID

	type kicked struct {
		findingID string
		future    workflow.Future
	}
	var fans []kicked
	for _, f := range accepted {
		msg := findingToMessage(f, channels.WorkflowRef{
			WorkflowID: workflowID,
			RunID:      runID,
			TraceURL:   temporalDeepLink(traceURLBase, workflowID, runID),
		})
		pf := workflow.ExecuteActivity(pctx, chtemporal.ActivityPost, msg)
		fans = append(fans, kicked{f.ID, pf})
	}

	var results []PostFindingsResult
	for _, k := range fans {
		var out chtemporal.PostResult
		if err := k.future.Get(ctx, &out); err != nil {
			results = append(results, PostFindingsResult{
				FindingID: k.findingID,
				Error:     err.Error(),
			})
			continue
		}
		var chs []string
		for _, r := range out.Receipts {
			chs = append(chs, r.Channel)
		}
		results = append(results, PostFindingsResult{
			FindingID: k.findingID,
			Posted:    len(out.Receipts) > 0,
			Channels:  chs,
			Receipts:  out.Receipts,
			Error:     joinErrors(out.Errors),
		})
	}
	return results
}

// awaitVerdicts is Phase 3c: fan-out one channel.AwaitVerdict activity per
// posted finding, in parallel. Each activity polls the channel (Slack
// reactions, etc.) for an authorized verdict until either a verdict arrives
// or opts.Timeout elapses.
//
// All waits run concurrently as durable Temporal activities. The function
// returns when every wait has resolved — either with a verdict, a timeout,
// or an activity error. Timeouts are not treated as failures; the audit
// proceeds and the report records "no verdict" for those findings.
//
// posted MUST come from a prior postFindings call. Findings without
// Posted=true are skipped (no receipts to wait on).
func awaitVerdicts(ctx workflow.Context, posted []PostFindingsResult, awaitOpts channels.AwaitOpts) []VerdictResult {
	// One activity per posted finding, all kicked off before any future.Get.
	// This is what makes the waits parallel: a 30-minute timeout on 5
	// findings takes 30 minutes, not 2.5 hours.
	wfOpts := workflow.ActivityOptions{
		// StartToCloseTimeout must exceed AwaitOpts.Timeout — Temporal
		// terminates an activity that runs past this, so we add a buffer.
		StartToCloseTimeout: awaitOpts.Timeout + 5*time.Minute,
		HeartbeatTimeout:    30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			// Don't retry on timeout — a timed-out wait is a deliberate
			// outcome, not a transient failure to recover from.
			MaximumAttempts: 1,
		},
	}
	wctx := workflow.WithActivityOptions(ctx, wfOpts)

	type kicked struct {
		findingID string
		future    workflow.Future
	}
	var fans []kicked
	for _, p := range posted {
		if !p.Posted || len(p.Receipts) == 0 {
			continue
		}
		f := workflow.ExecuteActivity(wctx, chtemporal.ActivityAwaitVerdict, p.Receipts, awaitOpts)
		fans = append(fans, kicked{p.FindingID, f})
	}

	var results []VerdictResult
	for _, k := range fans {
		var v channels.Verdict
		err := k.future.Get(ctx, &v)
		switch {
		case err == nil:
			results = append(results, VerdictResult{
				FindingID: k.findingID,
				Choice:    v.Choice,
				Actor:     v.Actor.Canonical,
				Channel:   v.Channel,
				At:        v.At,
			})
		case isTimeout(err):
			results = append(results, VerdictResult{
				FindingID: k.findingID,
				Timeout:   true,
			})
		default:
			results = append(results, VerdictResult{
				FindingID: k.findingID,
				Error:     err.Error(),
			})
		}
	}
	return results
}

// applyVerdicts mutates a slice of accepted findings in place, attaching
// each VerdictResult's data to the matching finding. Findings without a
// verdict are left untouched. Returns the slice for chaining.
func applyVerdicts(accepted []findings.Finding, verdicts []VerdictResult) []findings.Finding {
	if len(verdicts) == 0 {
		return accepted
	}
	byID := make(map[string]VerdictResult, len(verdicts))
	for _, v := range verdicts {
		byID[v.FindingID] = v
	}
	for i := range accepted {
		v, ok := byID[accepted[i].ID]
		if !ok || v.Choice == "" {
			continue
		}
		accepted[i].HumanVerdict = v.Choice
		accepted[i].HumanActor = v.Actor
		accepted[i].HumanVerdictAt = v.At
		accepted[i].HumanVerdictChannel = v.Channel
	}
	return accepted
}

// isTimeout reports whether the given error is the channels-level ErrTimeout
// produced when a wait completes without a valid verdict. Temporal wraps
// activity errors, so the underlying message is the most reliable signal.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return msg == channels.ErrTimeout.Error() || strings.Contains(msg, "timed out")
}

// countWithVerdict reports how many results carry a non-empty verdict choice.
func countWithVerdict(vs []VerdictResult) int {
	n := 0
	for _, v := range vs {
		if v.Choice != "" {
			n++
		}
	}
	return n
}

// countTimeouts reports how many results timed out without a verdict.
func countTimeouts(vs []VerdictResult) int {
	n := 0
	for _, v := range vs {
		if v.Timeout {
			n++
		}
	}
	return n
}

// countErrored reports how many results came back with an error string.
func countErrored(vs []VerdictResult) int {
	n := 0
	for _, v := range vs {
		if v.Error != "" {
			n++
		}
	}
	return n
}

// findingToMessage maps Sentry's domain Finding type onto the channel-package
// neutral Message type. This translation deliberately lives in the audit
// package (not channels/) so the channels package stays domain-agnostic and
// will lift unchanged into Sibyl.
func findingToMessage(f findings.Finding, ref channels.WorkflowRef) channels.Message {
	evidence := make([]channels.Evidence, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		evidence = append(evidence, channels.Evidence{
			Kind:        e.Kind,
			Description: e.Description,
			Location:    e.Location,
		})
	}

	return channels.Message{
		Subject: channels.Subject{Kind: "finding", ID: f.ID},
		Title:   f.Title,
		Body:    f.Description,
		// LLMRationale is the Critic's accepted rationale — surface it as the
		// final context line so reviewers see why the agents accepted this.
		Severity: toChannelSeverity(f.Severity),
		Evidence: evidence,
		Actions: []channels.Action{
			{ID: "accept", Label: "Confirm finding", Style: "primary"},
			{ID: "reject", Label: "False positive", Style: "danger"},
			{ID: "snooze", Label: "Defer", Style: "default"},
		},
		WorkflowRef: ref,
		Metadata: map[string]string{
			"category":        string(f.Category),
			"scanner_id":      f.ScannerID,
			"converge_rounds": intToStr(f.ConvergeRounds),
			"llm_rationale":   f.LLMRationale,
		},
	}
}

// toChannelSeverity converts findings.Severity → channels.Severity.
func toChannelSeverity(s findings.Severity) channels.Severity {
	switch s {
	case findings.SeverityCritical:
		return channels.SeverityCritical
	case findings.SeverityHigh:
		return channels.SeverityHigh
	case findings.SeverityMedium:
		return channels.SeverityMedium
	case findings.SeverityLow:
		return channels.SeverityLow
	default:
		return channels.SeverityInfo
	}
}

func temporalDeepLink(base, workflowID, runID string) string {
	if base == "" {
		return ""
	}
	// Standard Temporal Web UI workflow URL format.
	return base + "/namespaces/default/workflows/" + workflowID + "/" + runID + "/history"
}

func joinErrors(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	out := errs[0]
	for _, e := range errs[1:] {
		out += "; " + e
	}
	return out
}

func intToStr(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
