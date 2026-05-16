package audit

import (
	"strconv"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/vinodhalaharvi/sibyl-sentry/channels"
	chtemporal "github.com/vinodhalaharvi/sibyl-sentry/channels/temporal"
	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

// PostFindingsResult records the per-finding outcome of channel posting.
// Mirrors the shape of TicketResult so the UI can surface both consistently.
type PostFindingsResult struct {
	FindingID string
	Posted    bool
	Channels  []string // names of channels that received the post
	Error     string
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
			Error:     joinErrors(out.Errors),
		})
	}
	return results
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
