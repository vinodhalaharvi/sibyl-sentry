// Package audit defines SecurityAuditWorkflow — Sentry's domain-specific
// Supervisor workflow. Unlike Sibyl's heuristic decomposer (which splits
// natural-language questions), this workflow decomposes by a fixed
// security checklist: which scanners to run against the target.
//
// The workflow:
//  1. Resolves the checklist from the input (which scanners to run).
//  2. Fans out: one activity invocation per scanner, in parallel.
//  3. Each scanner's findings flow through a Critic step (when LLM is wired).
//  4. Synthesizes findings into a Report.
//  5. For findings above the severity threshold, fans out Jira ticket creation.
//
// For the hackathon scaffold this is the deterministic backbone; LLM-backed
// Critic + Researcher wraps come from Sibyl's ConvergeWorkflow once wired.
package audit

import (
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/jira"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/regex"
)

const WorkflowName = "SecurityAuditWorkflow"

// AuditInput is the workflow's input.
type AuditInput struct {
	// TargetPath is the directory to scan (typically a checked-out git repo).
	TargetPath string

	// Inventories points scanners at their JSON inputs. In production these
	// would be replaced by API-call activities; for the hackathon they're
	// paths into the fixtures repo.
	Inventories Inventories

	// EnabledScanners selects which scanners to run. Empty means all.
	EnabledScanners []ScannerID

	// FileTickets, if true, fans out Jira ticket creation after synthesis.
	FileTickets bool

	// MinTicketSeverity controls which findings get Jira tickets.
	MinTicketSeverity findings.Severity
}

// Inventories points scanners at their input data.
type Inventories struct {
	OAuthClients     string // path to oauth-clients.json
	ScopeGrants      string // path to scope-grants.json
	ScopeUsage       string // path to scope-usage.json
	ServiceAccounts  string // path to service-accounts.json
}

// ScannerID identifies a scanner in the checklist.
type ScannerID string

const (
	ScannerSecrets  ScannerID = "secrets"   // regex (or yara w/ build tag)
	ScannerOAuth    ScannerID = "oauth"
	// Future:
	ScannerScopes   ScannerID = "scopes"
	ScannerReuse    ScannerID = "reuse"
	ScannerDormancy ScannerID = "dormancy"
)

// AuditOutput is the synthesized result.
type AuditOutput struct {
	Report  findings.Report
	Tickets []TicketResult
}

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
	log.Info("audit start", "target", in.TargetPath)

	startedAt := workflow.Now(ctx)

	enabled := in.EnabledScanners
	if len(enabled) == 0 {
		enabled = []ScannerID{ScannerSecrets, ScannerOAuth}
	}

	// Long scans need patient activity timeouts and heartbeats. Regex scan
	// on a small fixture repo is fast, but YARA + history on a real repo
	// can take minutes.
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

	// Fan-out: schedule every enabled scanner in parallel.
	type scannerResult struct {
		id       ScannerID
		findings []findings.Finding
		err      error
	}
	futures := make(map[ScannerID]workflow.Future, len(enabled))
	for _, id := range enabled {
		switch id {
		case ScannerSecrets:
			f := workflow.ExecuteActivity(ctx, regex.ActivityName, regex.ScanInput{
				TargetPath:  in.TargetPath,
				ScanHistory: true,
			})
			futures[id] = f
		case ScannerOAuth:
			if in.Inventories.OAuthClients == "" {
				log.Warn("oauth scanner enabled but no inventory path; skipping")
				continue
			}
			f := workflow.ExecuteActivity(ctx, oauth.ActivityName, oauth.ScanInput{
				InventoryPath: in.Inventories.OAuthClients,
			})
			futures[id] = f
		default:
			log.Warn("scanner not yet implemented", "id", id)
		}
	}

	// Gather: wait for each future; record errors but don't abort.
	results := make([]scannerResult, 0, len(futures))
	for id, f := range futures {
		switch id {
		case ScannerSecrets:
			var out regex.ScanOutput
			err := f.Get(ctx, &out)
			results = append(results, scannerResult{id: id, findings: out.Findings, err: err})
		case ScannerOAuth:
			var out oauth.ScanOutput
			err := f.Get(ctx, &out)
			results = append(results, scannerResult{id: id, findings: out.Findings, err: err})
		}
	}

	// Synthesize: assemble the Report.
	report := findings.Report{
		Target:      in.TargetPath,
		StartedAt:   startedAt,
		CompletedAt: workflow.Now(ctx),
	}
	for _, r := range results {
		if r.err != nil {
			report.Errors = append(report.Errors,
				fmt.Sprintf("%s: %v", r.id, r.err))
			continue
		}
		report.Findings = append(report.Findings, r.findings...)
	}

	// File tickets if enabled.
	var tickets []TicketResult
	if in.FileTickets && len(report.Findings) > 0 {
		ticketOpts := workflow.ActivityOptions{
			StartToCloseTimeout: 30 * time.Second,
			RetryPolicy: &temporal.RetryPolicy{
				InitialInterval:    time.Second,
				BackoffCoefficient: 2,
				MaximumAttempts:    3,
			},
		}
		tctx := workflow.WithActivityOptions(ctx, ticketOpts)

		ticketFutures := make([]workflow.Future, 0, len(report.Findings))
		for _, f := range report.Findings {
			tf := workflow.ExecuteActivity(tctx, jira.ActivityName, jira.CreateTicketInput{
				Finding:     f,
				MinSeverity: in.MinTicketSeverity,
			})
			ticketFutures = append(ticketFutures, tf)
		}
		for i, tf := range ticketFutures {
			var out jira.CreateTicketOutput
			if err := tf.Get(ctx, &out); err != nil {
				log.Warn("ticket creation failed", "finding", report.Findings[i].ID, "err", err)
				continue
			}
			tickets = append(tickets, TicketResult{
				FindingID: report.Findings[i].ID,
				Filed:     out.Filed,
				Key:       out.TicketKey,
				URL:       out.TicketURL,
				Skip:      out.SkipReason,
			})
		}
	}

	log.Info("audit complete",
		"findings", len(report.Findings),
		"errors", len(report.Errors),
		"tickets", len(tickets),
	)
	return &AuditOutput{Report: report, Tickets: tickets}, nil
}
