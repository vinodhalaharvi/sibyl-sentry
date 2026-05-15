// Package findings defines the shared shape of every security finding
// Sentry produces. Scanners populate Findings; the Critic evaluates them;
// the synthesizer ranks and groups them; the Jira agent files them.
package findings

import "time"

// Severity is the urgency of a finding. Higher value = more urgent.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Category groups findings by the kind of issue. Used for routing,
// deduplication, and the synthesizer's per-section ordering.
type Category string

const (
	CategorySecretExposure   Category = "secret_exposure"
	CategoryStaleOAuth       Category = "stale_oauth"
	CategoryOverPrivilege    Category = "over_privilege"
	CategoryTokenReuse       Category = "token_reuse"
	CategoryDormantAccount   Category = "dormant_account"
)

// Evidence is a single piece of proof attached to a finding. The Critic
// rejects findings whose evidence doesn't actually support the claim, so
// scanners should attach concrete, verifiable details — file:line, commit
// SHA, API response field, etc.
type Evidence struct {
	// Kind is a short tag describing what this evidence is.
	// Examples: "file_line", "git_commit", "api_field", "cross_file_match".
	Kind string `json:"kind"`

	// Description is human-readable evidence text shown in the brief.
	Description string `json:"description"`

	// Location is where the evidence was found (path:line, commit SHA, API endpoint).
	Location string `json:"location,omitempty"`

	// Snippet is a short verbatim excerpt that demonstrates the finding.
	// Keep this brief — the goal is "here's the exact thing I'm pointing at".
	Snippet string `json:"snippet,omitempty"`
}

// Finding is one security issue surfaced by a scanner. The Critic decides
// whether to accept or reject it; the synthesizer composes accepted findings
// into the final brief; the Jira agent files high-severity ones.
type Finding struct {
	// ID is a stable identifier for deduplication. Scanners are responsible
	// for making this deterministic (e.g. category + location hash) so reruns
	// don't double-count.
	ID string `json:"id"`

	// Category groups findings of the same kind together.
	Category Category `json:"category"`

	// Severity is the urgency.
	Severity Severity `json:"severity"`

	// Title is a short headline. Should make sense on its own in a list.
	// Examples: "AWS access key in apps/billing-service/config/prod.env",
	// "OAuth client 0oa1stale8 unused for 21 months".
	Title string `json:"title"`

	// Description explains the finding and why it's a problem.
	Description string `json:"description"`

	// Evidence is the supporting proof. The Critic checks that this is
	// non-empty and actually demonstrates the claim in the title.
	Evidence []Evidence `json:"evidence"`

	// OwnerHint is what the scanner thinks the owner is — a path prefix,
	// an email, or a client ID. The owners resolver translates this into
	// a Jira project + assignee.
	OwnerHint string `json:"owner_hint,omitempty"`

	// DiscoveredAt is when the scanner produced this finding.
	DiscoveredAt time.Time `json:"discovered_at"`

	// ScannerID identifies which scanner produced this (for debugging).
	ScannerID string `json:"scanner_id"`

	// --- LLM-converged fields, populated after Researcher/Critic runs ---

	// LLMRationale is the Researcher's justification for accepting this
	// finding, as approved by the Critic. Empty if the finding bypassed
	// the convergence loop (shouldn't happen in production paths).
	LLMRationale string `json:"llm_rationale,omitempty"`

	// ConvergedAt is when the ConvergeWorkflow approved this finding.
	// Zero value means convergence didn't run (legacy/scanner-only).
	ConvergedAt time.Time `json:"converged_at,omitempty"`

	// ConvergeRounds is how many Researcher/Critic iterations this
	// finding required before approval. 0 means convergence didn't run.
	ConvergeRounds int `json:"converge_rounds,omitempty"`

	// ConvergeWorkflowID is the Temporal workflow ID for the
	// ConvergeWorkflow that approved this finding. The web UI uses this
	// to deep-link to the Temporal Web UI's workflow detail page.
	ConvergeWorkflowID string `json:"converge_workflow_id,omitempty"`
}

// RejectedFinding records a candidate that the Critic refused to accept.
// Keeping these in the report serves two purposes:
//
//   1. The audit team can see what the agent considered and rejected —
//      transparency about false-positive filtering.
//   2. If the rejection was wrong (rare but possible), the rejected list
//      surfaces it for human review rather than swallowing it silently.
type RejectedFinding struct {
	Candidate          Finding   `json:"candidate"`
	Reason             string    `json:"reason"`
	RejectedAt         time.Time `json:"rejected_at"`
	ConvergeRounds     int       `json:"converge_rounds"`
	ConvergeWorkflowID string    `json:"converge_workflow_id,omitempty"`
}

// Report is the synthesized output of an audit — multiple findings across
// multiple scanners, plus metadata about the audit itself.
type Report struct {
	Target      string    `json:"target"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`

	// Findings are the candidates accepted by the Researcher/Critic loop.
	Findings []Finding `json:"findings"`

	// Rejected are the candidates the Critic refused to publish. Kept
	// for transparency — the audit team can see what the agent dismissed
	// and why.
	Rejected []RejectedFinding `json:"rejected,omitempty"`

	// Errors are scanner-level errors (e.g. a vendor API was unreachable).
	Errors []string `json:"errors,omitempty"`
}
