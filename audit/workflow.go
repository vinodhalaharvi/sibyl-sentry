// Package audit defines SecurityAuditWorkflow — Sentry's domain-specific
// Supervisor workflow that orchestrates the agentic security audit.
//
// Architecture (the "LLM DAG" — every candidate finding goes through a
// Researcher/Critic convergence before it appears in the report):
//
//	┌────────────────────────────────────────────────────────────┐
//	│ Phase 1: SCANNER FAN-OUT (deterministic data fetch)        │
//	│                                                            │
//	│  regex.Scan      (works the filesystem + git history)      │
//	│  oauth.ScanStale (HTTP → mock-okta)                        │
//	│  scopes.Scan     (HTTP → mock-okta)                        │
//	│  dormancy.Scan   (HTTP → mock-aws)                         │
//	│                                                            │
//	│  Each returns a list of CANDIDATE findings — evidence-only,│
//	│  no judgment. Pure data, scanner-assigned initial severity.│
//	└──────────────────────────┬─────────────────────────────────┘
//	                           │ candidates pooled
//	┌──────────────────────────▼─────────────────────────────────┐
//	│ Phase 2: CONVERGENCE FAN-OUT (agentic judgment, parallel)  │
//	│                                                            │
//	│  For each candidate, spawn a ConvergeWorkflow CHILD:       │
//	│                                                            │
//	│    Round 1: Researcher reads candidate + evidence,         │
//	│             writes DECISION + SEVERITY + RATIONALE.        │
//	│    Round 2: Critic evaluates Researcher's answer.          │
//	│             If approved → return.                          │
//	│             Else, Researcher revises with Critic feedback. │
//	│    Round 3: final revision if still not converged.         │
//	│                                                            │
//	│  Each ConvergeWorkflow is its own Temporal workflow,       │
//	│  visible in the Web UI with its own event history.         │
//	│  Sentry's UI deep-links findings to their Converge ID.     │
//	└──────────────────────────┬─────────────────────────────────┘
//	                           │ accepted / rejected
//	┌──────────────────────────▼─────────────────────────────────┐
//	│ Phase 3: SYNTHESIS                                         │
//	│   Build Report{Findings: accepted, Rejected: refused}.     │
//	│   If FileTickets, fan-out Jira ticket creation per finding.│
//	└────────────────────────────────────────────────────────────┘
//
// The agentic part is Phase 2. Without it, Sentry is just a deterministic
// scanner runner. With it, every published finding has been challenged
// by a Critic and survives — false positives get filtered, severities
// get re-justified against evidence, descriptions get rewritten in
// reviewer-friendly prose.
package audit

import (
	"fmt"
	"strings"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
	"github.com/vinodhalaharvi/sibyl-sentry/jira"
	"github.com/vinodhalaharvi/sibyl-sentry/prompts"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/dormancy"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/regex"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/scopes"
)

const WorkflowName = "SecurityAuditWorkflow"

// AuditInput is the workflow's input.
type AuditInput struct {
	TargetPath        string
	VendorEndpoints   VendorEndpoints
	EnabledScanners   []ScannerID
	FileTickets       bool
	MinTicketSeverity findings.Severity

	// SkipConvergence, if true, publishes scanner candidates directly
	// without running them through the Researcher/Critic loop. Useful for
	// debugging the data path or for environments without LLM access.
	// Default: false (always converge).
	SkipConvergence bool

	// MaxCandidatesPerScanner caps how many candidates from each scanner
	// are passed to convergence. 0 means unlimited. Set to a small number
	// (e.g. 5) to bound LLM fan-out for demos / rate-limited environments.
	// Scanners typically return candidates in priority/severity order, so
	// the cap keeps the most important findings.
	MaxCandidatesPerScanner int

	// PostToChannels, when true, posts each accepted finding to configured
	// human-facing channels (Slack, etc.) via the channels package. Requires
	// channels activities to be registered on the worker. Default false:
	// existing behavior is preserved unless explicitly opted in.
	PostToChannels bool

	// ChannelTraceURLBase is the Temporal Web UI base URL used to build
	// deep-links in posted messages. Typical value: "http://localhost:8233".
	// Optional; if empty, posted messages will not include a trace link.
	ChannelTraceURLBase string
}

// VendorEndpoints groups per-vendor connection config.
type VendorEndpoints struct {
	OktaBaseURL   string
	OktaToken     string
	AWSBaseURL    string
	AWSToken      string
	GitHubBaseURL string
	GitHubToken   string
}

// ScannerID identifies a scanner in the checklist.
type ScannerID string

const (
	ScannerSecrets  ScannerID = "secrets"
	ScannerOAuth    ScannerID = "oauth"
	ScannerScopes   ScannerID = "scopes"
	ScannerDormancy ScannerID = "dormancy"
)

// AuditOutput is the synthesized result.
type AuditOutput struct {
	Report       findings.Report
	Tickets      []TicketResult
	ChannelPosts []PostFindingsResult
}

// TicketResult records the outcome of each ticket-creation attempt.
type TicketResult struct {
	FindingID string
	Filed     bool
	Key       string
	URL       string
	Skip      string
}

// SecurityAuditWorkflow is the entry point.
func SecurityAuditWorkflow(ctx workflow.Context, in AuditInput) (*AuditOutput, error) {
	log := workflow.GetLogger(ctx)
	log.Info("audit start", "target", in.TargetPath, "skip_convergence", in.SkipConvergence)

	startedAt := workflow.Now(ctx)

	// === Phase 1: scanner fan-out ============================================

	candidates, scanErrors := runScanners(ctx, in)
	log.Info("scanners complete",
		"candidates", len(candidates),
		"errors", len(scanErrors))

	// === Phase 2: convergence fan-out =======================================

	var accepted []findings.Finding
	var rejected []findings.RejectedFinding

	if in.SkipConvergence {
		// Bypass mode — publish candidates directly. Mostly for debugging.
		log.Warn("convergence skipped — publishing scanner candidates directly")
		accepted = candidates
	} else {
		accepted, rejected = runConvergence(ctx, candidates)
		log.Info("convergence complete",
			"accepted", len(accepted), "rejected", len(rejected))
	}

	// === Phase 3: synthesis + ticket fan-out ================================

	report := findings.Report{
		Target:      in.TargetPath,
		StartedAt:   startedAt,
		CompletedAt: workflow.Now(ctx),
		Findings:    accepted,
		Rejected:    rejected,
		Errors:      scanErrors,
	}

	var tickets []TicketResult
	if in.FileTickets && len(report.Findings) > 0 {
		tickets = fileTickets(ctx, report.Findings, in.MinTicketSeverity)
	}

	var channelPosts []PostFindingsResult
	if in.PostToChannels && len(report.Findings) > 0 {
		channelPosts = postFindings(ctx, report.Findings, in.ChannelTraceURLBase)
	}

	log.Info("audit complete",
		"findings_accepted", len(report.Findings),
		"findings_rejected", len(report.Rejected),
		"errors", len(report.Errors),
		"tickets", len(tickets),
		"channel_posts", len(channelPosts))
	return &AuditOutput{Report: report, Tickets: tickets, ChannelPosts: channelPosts}, nil
}

// runScanners is Phase 1: schedule every enabled scanner in parallel,
// gather candidates from each. Errors are collected, not fatal — a
// failing scanner doesn't poison the whole audit.
func runScanners(ctx workflow.Context, in AuditInput) ([]findings.Finding, []string) {
	enabled := in.EnabledScanners
	if len(enabled) == 0 {
		// Default: every scanner whose required config is set.
		if in.TargetPath != "" {
			enabled = append(enabled, ScannerSecrets)
		}
		if in.VendorEndpoints.OktaBaseURL != "" {
			enabled = append(enabled, ScannerOAuth, ScannerScopes)
		}
		if in.VendorEndpoints.AWSBaseURL != "" {
			enabled = append(enabled, ScannerDormancy)
		}
	}

	scanOpts := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		HeartbeatTimeout:    1 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    30 * time.Second,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, scanOpts)

	type kicked struct {
		id     ScannerID
		future workflow.Future
	}
	var fans []kicked
	for _, id := range enabled {
		switch id {
		case ScannerSecrets:
			if in.TargetPath == "" {
				continue
			}
			f := workflow.ExecuteActivity(ctx, regex.ActivityName, regex.ScanInput{
				TargetPath:  in.TargetPath,
				ScanHistory: true,
			})
			fans = append(fans, kicked{id, f})
		case ScannerOAuth:
			if in.VendorEndpoints.OktaBaseURL == "" {
				continue
			}
			f := workflow.ExecuteActivity(ctx, oauth.ActivityName, oauth.ScanInput{
				OktaBaseURL: in.VendorEndpoints.OktaBaseURL,
				OktaToken:   in.VendorEndpoints.OktaToken,
			})
			fans = append(fans, kicked{id, f})
		case ScannerScopes:
			if in.VendorEndpoints.OktaBaseURL == "" {
				continue
			}
			f := workflow.ExecuteActivity(ctx, scopes.ActivityName, scopes.ScanInput{
				OktaBaseURL: in.VendorEndpoints.OktaBaseURL,
				OktaToken:   in.VendorEndpoints.OktaToken,
			})
			fans = append(fans, kicked{id, f})
		case ScannerDormancy:
			if in.VendorEndpoints.AWSBaseURL == "" {
				continue
			}
			f := workflow.ExecuteActivity(ctx, dormancy.ActivityName, dormancy.ScanInput{
				AWSBaseURL: in.VendorEndpoints.AWSBaseURL,
				AWSToken:   in.VendorEndpoints.AWSToken,
			})
			fans = append(fans, kicked{id, f})
		}
	}

	var candidates []findings.Finding
	var errs []string
	cap := in.MaxCandidatesPerScanner
	clip := func(fs []findings.Finding) []findings.Finding {
		if cap > 0 && len(fs) > cap {
			return fs[:cap]
		}
		return fs
	}
	for _, k := range fans {
		var err error
		switch k.id {
		case ScannerSecrets:
			var out regex.ScanOutput
			err = k.future.Get(ctx, &out)
			candidates = append(candidates, clip(out.Findings)...)
		case ScannerOAuth:
			var out oauth.ScanOutput
			err = k.future.Get(ctx, &out)
			candidates = append(candidates, clip(out.Findings)...)
		case ScannerScopes:
			var out scopes.ScanOutput
			err = k.future.Get(ctx, &out)
			candidates = append(candidates, clip(out.Findings)...)
		case ScannerDormancy:
			var out dormancy.ScanOutput
			err = k.future.Get(ctx, &out)
			candidates = append(candidates, clip(out.Findings)...)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k.id, err))
		}
	}
	return candidates, errs
}

// runConvergence is Phase 2: for each candidate, spawn a ConvergeWorkflow
// child to evaluate it through Researcher/Critic. All run in parallel.
//
// Why child workflows and not activities: each ConvergeWorkflow has its
// own event history in Temporal Web UI, so judges (and future engineers)
// can drill into the per-finding reasoning. With activities, all calls
// pile into the parent workflow's history and become hard to read.
//
// Each child workflow ID is derived from the candidate ID, so the
// Sentry UI can deep-link to the right Temporal page.
func runConvergence(ctx workflow.Context, candidates []findings.Finding) ([]findings.Finding, []findings.RejectedFinding) {
	if len(candidates) == 0 {
		return nil, nil
	}

	parentID := workflow.GetInfo(ctx).WorkflowExecution.ID

	// Light activity options for the convergence event emits — these are
	// fire-and-forget log messages, not durable state.
	emitCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    100 * time.Millisecond,
			BackoffCoefficient: 1.5,
			MaximumAttempts:    2,
		},
	})

	type kicked struct {
		candidate  findings.Finding
		future     workflow.ChildWorkflowFuture
		childWfID  string
		startedAt  time.Time
	}
	var fans []kicked

	for _, c := range candidates {
		childWfID := childWorkflowID(parentID, c.ID)

		childOpts := workflow.ChildWorkflowOptions{
			WorkflowID:        childWfID,
			TaskQueue:         workflow.GetInfo(ctx).TaskQueueName,
			WorkflowRunTimeout: 5 * time.Minute,
			ParentClosePolicy: 1,
		}
		childCtx := workflow.WithChildOptions(ctx, childOpts)

		question := sibylproxy.Question{
			Text:      prompts.FormatCandidate(c),
			MaxRounds: prompts.MaxRounds,
		}
		f := workflow.ExecuteChildWorkflow(childCtx,
			sibylproxy.ConvergeWorkflowName,
			question,
		)

		// Emit node.started for this converge child. Synchronous —
		// .Get() blocks until the activity completes. With many
		// candidates this adds a few seconds total, but eliminates any
		// possible non-determinism from fire-and-forget scheduling.
		_ = workflow.ExecuteActivity(emitCtx, "ConvergeEmitActivity", ConvergeEmitInput{
			ParentWorkflowID: parentID,
			Kind:             "node.started",
			CandidateID:      c.ID,
			CandidateTitle:   c.Title,
			ChildWorkflowID:  childWfID,
		}).Get(ctx, nil)

		fans = append(fans, kicked{candidate: c, future: f, childWfID: childWfID, startedAt: workflow.Now(ctx)})
	}

	var accepted []findings.Finding
	var rejected []findings.RejectedFinding

	for _, k := range fans {
		var answer sibylproxy.Answer
		if err := k.future.Get(ctx, &answer); err != nil {
			// Convergence itself failed (timeout, crash). Treat the
			// candidate as rejected with the error as the reason — the
			// audit report includes the failure for transparency.
			rejected = append(rejected, findings.RejectedFinding{
				Candidate:          k.candidate,
				Reason:             "convergence workflow failed: " + err.Error(),
				RejectedAt:         workflow.Now(ctx),
				ConvergeWorkflowID: k.childWfID,
			})
			_ = workflow.ExecuteActivity(emitCtx, "ConvergeEmitActivity", ConvergeEmitInput{
				ParentWorkflowID: parentID,
				Kind:             "node.failed",
				CandidateID:      k.candidate.ID,
				CandidateTitle:   k.candidate.Title,
				ChildWorkflowID:  k.childWfID,
				Reason:           "workflow error: " + err.Error(),
				DurationMs:       workflow.Now(ctx).Sub(k.startedAt).Milliseconds(),
			}).Get(ctx, nil)
			continue
		}

		result := prompts.ParseConvergedAnswer(answer.Text)
		now := workflow.Now(ctx)
		durMs := now.Sub(k.startedAt).Milliseconds()

		if result.Accepted {
			final := k.candidate
			final.Severity = result.Severity
			final.LLMRationale = result.Rationale
			if result.Description != "" {
				final.Description = result.Description
			}
			final.ConvergedAt = now
			final.ConvergeRounds = answer.Rounds
			final.ConvergeWorkflowID = k.childWfID
			accepted = append(accepted, final)
			_ = workflow.ExecuteActivity(emitCtx, "ConvergeEmitActivity", ConvergeEmitInput{
				ParentWorkflowID:     parentID,
				Kind:                 "node.completed",
				CandidateID:          k.candidate.ID,
				CandidateTitle:       k.candidate.Title,
				CandidateDescription: final.Description,
				ChildWorkflowID:      k.childWfID,
				Severity:             result.Severity.String(),
				Rounds:               answer.Rounds,
				Accepted:             true,
				Rationale:            result.Rationale,
				DurationMs:           durMs,
			}).Get(ctx, nil)
		} else {
			reason := result.Rationale
			if reason == "" {
				reason = "rejected by Critic (no rationale provided)"
			}
			rejected = append(rejected, findings.RejectedFinding{
				Candidate:          k.candidate,
				Reason:             reason,
				RejectedAt:         now,
				ConvergeRounds:     answer.Rounds,
				ConvergeWorkflowID: k.childWfID,
			})
			_ = workflow.ExecuteActivity(emitCtx, "ConvergeEmitActivity", ConvergeEmitInput{
				ParentWorkflowID: parentID,
				Kind:             "node.failed",
				CandidateID:      k.candidate.ID,
				CandidateTitle:   k.candidate.Title,
				ChildWorkflowID:  k.childWfID,
				Reason:           reason,
				Rounds:           answer.Rounds,
				DurationMs:       durMs,
			}).Get(ctx, nil)
		}
	}

	return accepted, rejected
}

// childWorkflowID composes a deterministic Converge workflow ID from the
// parent audit ID and the candidate's finding ID. Determinism matters —
// Temporal rejects duplicate workflow IDs, so we encode enough uniqueness
// (parent + finding) to avoid collisions even when an audit is re-run.
func childWorkflowID(parentWfID, candidateID string) string {
	// Strip the "sentry-audit-" prefix from the parent ID so the
	// composed name stays readable.
	short := strings.TrimPrefix(parentWfID, "sentry-audit-")
	// Some candidate IDs may include characters Temporal allows but the
	// web UI URL-encodes awkwardly; we keep them but limit length.
	safeCand := candidateID
	if len(safeCand) > 60 {
		safeCand = safeCand[:60]
	}
	return fmt.Sprintf("converge-%s-%s", short, safeCand)
}

// fileTickets is Phase 3 fan-out: one Jira ticket activity per accepted
// finding. Activities decide whether to actually file based on severity.
func fileTickets(ctx workflow.Context, accepted []findings.Finding, minSev findings.Severity) []TicketResult {
	ticketOpts := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2,
			MaximumAttempts:    3,
		},
	}
	tctx := workflow.WithActivityOptions(ctx, ticketOpts)

	type kicked struct {
		findingID string
		future    workflow.Future
	}
	var fans []kicked
	for _, f := range accepted {
		tf := workflow.ExecuteActivity(tctx, jira.ActivityName, jira.CreateTicketInput{
			Finding:     f,
			MinSeverity: minSev,
		})
		fans = append(fans, kicked{f.ID, tf})
	}

	var results []TicketResult
	for _, k := range fans {
		var out jira.CreateTicketOutput
		if err := k.future.Get(ctx, &out); err != nil {
			results = append(results, TicketResult{
				FindingID: k.findingID, Skip: "error: " + err.Error(),
			})
			continue
		}
		results = append(results, TicketResult{
			FindingID: k.findingID,
			Filed:     out.Filed,
			Key:       out.TicketKey,
			URL:       out.TicketURL,
			Skip:      out.SkipReason,
		})
	}
	return results
}
