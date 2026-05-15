// Package prompts converts Sentry candidate findings into Sibyl
// ConvergeWorkflow questions, and parses the converged answers back into
// final findings (accepted or rejected).
//
// The flow:
//
//   Scanner emits a candidate finding (deterministic, evidence-only).
//        ↓
//   prompts.FormatCandidate constructs a Question{Text, MaxRounds} that
//   asks the Researcher to evaluate the candidate, write a justified
//   severity and description, and explicitly state ACCEPTED or REJECTED.
//        ↓
//   ConvergeWorkflow runs Researcher and Critic in a loop until the
//   Critic approves or MaxRounds is reached.
//        ↓
//   prompts.ParseConvergedAnswer reads Answer.Text and returns either
//   a final Finding (with LLM-justified severity and description) or
//   a RejectedFinding (with the rejection reason).
//
// Why a separate package: keeps the security-domain prompts out of the
// generic Sibyl engine, and out of the audit workflow itself. The
// workflow stays "do the orchestration"; the prompts stay "say the
// right thing to Claude." Both are independently testable.
package prompts

import (
	"fmt"
	"strings"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

// MaxRounds is how many Researcher/Critic iterations a candidate can go
// through before we give up. Three is a good default: round 1 produces
// the candidate, round 2 incorporates Critic feedback, round 3 is the
// last revision. Past three the agents tend to circle.
const MaxRounds = 3

// FormatCandidate produces the prompt text shown to the Researcher when
// evaluating a single candidate finding. The text packages everything
// the Researcher needs to make a justified judgment:
//
//   - What the scanner found (category, title, evidence)
//   - Where it was found (location, surrounding context if available)
//   - What "accepted" means for this finding type
//   - The required output format (so we can parse the result)
//
// The Critic doesn't need a separate function — Sibyl's generic Critic
// is given the Researcher's output and asks "does this answer the
// question well?". That works for us because our Researcher's output is
// already structured around the question.
func FormatCandidate(candidate findings.Finding) string {
	var b strings.Builder

	fmt.Fprintf(&b, "You are evaluating a security audit finding produced by a deterministic scanner. ")
	fmt.Fprintf(&b, "Your job is to decide whether this is a real, actionable finding ")
	fmt.Fprintf(&b, "or a false positive that should be filtered out.\n\n")

	fmt.Fprintf(&b, "## Candidate finding\n\n")
	fmt.Fprintf(&b, "- Category: %s\n", candidate.Category)
	fmt.Fprintf(&b, "- Initial severity (scanner-assigned): %s\n", candidate.Severity)
	fmt.Fprintf(&b, "- Scanner: %s\n", candidate.ScannerID)
	fmt.Fprintf(&b, "- Title: %s\n", candidate.Title)
	fmt.Fprintf(&b, "- Description: %s\n\n", candidate.Description)

	fmt.Fprintf(&b, "## Evidence\n\n")
	if len(candidate.Evidence) == 0 {
		fmt.Fprintf(&b, "(no evidence cited)\n\n")
	} else {
		for i, e := range candidate.Evidence {
			fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, e.Kind, e.Description)
			if e.Location != "" {
				fmt.Fprintf(&b, "   location: %s\n", e.Location)
			}
			if e.Snippet != "" {
				fmt.Fprintf(&b, "   snippet:  %s\n", oneLineSnippet(e.Snippet))
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Judgment criteria\n\n")
	fmt.Fprintf(&b, "%s\n\n", criteriaFor(candidate.Category))

	fmt.Fprintf(&b, "## Required output format\n\n")
	fmt.Fprintf(&b, "Respond with exactly the following structure (case-sensitive labels):\n\n")
	fmt.Fprintf(&b, "DECISION: <ACCEPTED|REJECTED>\n")
	fmt.Fprintf(&b, "SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|INFO>\n")
	fmt.Fprintf(&b, "RATIONALE: <one paragraph explaining your decision. Cite specific evidence ")
	fmt.Fprintf(&b, "by quoting from the evidence list above. If REJECTED, name the specific ")
	fmt.Fprintf(&b, "reason (test fixture, example file, public-by-design, etc).>\n")
	fmt.Fprintf(&b, "REVISED_DESCRIPTION: <a 1-3 sentence description suitable for a security ")
	fmt.Fprintf(&b, "engineer reading the final report. Specific, concrete, no hedging.>\n\n")

	fmt.Fprintf(&b, "Do not invent evidence. If the evidence is insufficient to accept, reject. ")
	fmt.Fprintf(&b, "If you are unsure, prefer rejection — a false positive in production wastes ")
	fmt.Fprintf(&b, "the security team's time more than a missed finding wastes a single audit.\n")

	return b.String()
}

// criteriaFor returns the category-specific judgment criteria appended
// to every prompt. These are what differentiate one Researcher run from
// another — they encode the domain knowledge the Critic enforces.
func criteriaFor(cat findings.Category) string {
	switch cat {
	case findings.CategorySecretExposure:
		return `ACCEPT only if the evidence shows a credential that an attacker could use
to gain real access. REJECT if any of the following apply:
- The path contains test/_test/fixture/example markers in a way consistent
  with intentional test data.
- The credential is a well-known placeholder (AKIAIOSFODNN7EXAMPLE, all-zero
  keys, vendor docs samples).
- A surrounding comment, function name, or struct tag explicitly identifies
  it as a fixture (TestOnly, MockKey, Example, DoNotUse).
- The file path is .md, .txt or doc-shaped AND the string is clearly an
  illustration rather than a working credential.
History findings (origin: git_history) are MORE serious than working-tree
findings: they cannot be removed by a simple commit and likely indicate
the credential was active long enough to be used.`

	case findings.CategoryStaleOAuth:
		return `ACCEPT only if the evidence shows last_used > 365 days ago AND status is
ACTIVE. REJECT if:
- The gap is below 365 days (quarterly scripts and seasonal tools have
  legitimately long idle periods).
- The client is already disabled or in a tombstoned state.
- The client's name strongly implies one-time-use migration / backfill
  tooling that's intentionally retained for re-runs.
The severity scales with the gap: >2 years CRITICAL, >1 year HIGH, otherwise
the candidate should not have been flagged in the first place.`

	case findings.CategoryOverPrivilege:
		return `ACCEPT only if the Researcher can name specific granted scopes that are
NOT in the recently-used scope list. REJECT if:
- The unused list is empty or fewer than 2 of N granted scopes.
- The unused scopes are clearly redundant (e.g. *.read when *.manage
  implies read) — say so explicitly in the rationale.
- The grant is read-only and the unused scopes are also read-only.
Severity scales with the fraction of unused scopes: >66% unused HIGH,
>33% MEDIUM, otherwise LOW or REJECTED.`

	case findings.CategoryDormantAccount:
		return `ACCEPT only if the evidence shows an Active access key whose LastUsedDate
is past 180 days. REJECT if:
- All access keys are Inactive or rotated within the window.
- The user is tagged as break-glass / emergency / disaster-recovery — these
  are SUPPOSED to be dormant and only used in incidents.
- The account is for a quarterly/annual job that legitimately sleeps long
  between runs.
Severity escalates with idle time (>24 months CRITICAL) and key count
(2+ dormant active keys is always CRITICAL — multiple keys means multiple
exfiltration paths).`

	default:
		return `ACCEPT only if the evidence concretely supports the claim. REJECT if the
evidence is circumstantial, the location is clearly a fixture/test/example,
or the severity is not justifiable from the cited evidence.`
	}
}

// oneLineSnippet truncates and one-lines an evidence snippet for prompt
// formatting. Multi-line snippets confuse the Researcher's structured
// output reader; we keep it to ~120 chars on one line.
func oneLineSnippet(s string) string {
	s = strings.ReplaceAll(s, "\n", " | ")
	s = strings.ReplaceAll(s, "\r", "")
	const max = 120
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

// ConvergenceResult is the parsed structured output of a Researcher's
// final converged answer. The audit workflow uses this to decide whether
// to publish the finding or record it as rejected.
type ConvergenceResult struct {
	// Accepted is true if the Researcher's DECISION line is ACCEPTED.
	Accepted bool

	// Severity is the Researcher's reassigned severity. May differ from
	// the scanner's initial severity — that's the point of the loop.
	Severity findings.Severity

	// Rationale is the Researcher's explanation. Always populated.
	// For rejections, this is the reason; for accepts, it's the
	// justification the report will display.
	Rationale string

	// Description is the LLM-rewritten finding description, intended for
	// display in the final report. Empty if parsing failed.
	Description string

	// RawAnswer is the full unparsed text, kept so the UI can show the
	// model's literal output for debugging or transparency.
	RawAnswer string
}

// ParseConvergedAnswer reads the Researcher's final answer text and
// returns the structured result. Tolerant of minor formatting variation:
// labels are matched case-insensitively, leading whitespace trimmed.
//
// If the LLM produced something we can't parse (unstructured prose, etc),
// the result has Accepted=false and Rationale="unparseable LLM output:
// <truncated text>" — we err on rejection because an unparseable answer
// is itself a signal something went wrong.
func ParseConvergedAnswer(raw string) ConvergenceResult {
	result := ConvergenceResult{RawAnswer: raw}
	lines := strings.Split(raw, "\n")

	var (
		decisionStr    string
		severityStr    string
		rationale      []string
		description    []string
		curField       string
	)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// preserve paragraph breaks inside multi-line fields
			if curField == "rationale" {
				rationale = append(rationale, "")
			}
			if curField == "description" {
				description = append(description, "")
			}
			continue
		}
		// Match a label prefix?
		if v, ok := matchPrefix(trimmed, "DECISION:"); ok {
			decisionStr = strings.ToUpper(strings.TrimSpace(v))
			curField = "decision"
			continue
		}
		if v, ok := matchPrefix(trimmed, "SEVERITY:"); ok {
			severityStr = strings.ToUpper(strings.TrimSpace(v))
			curField = "severity"
			continue
		}
		if v, ok := matchPrefix(trimmed, "RATIONALE:"); ok {
			rationale = append(rationale, strings.TrimSpace(v))
			curField = "rationale"
			continue
		}
		if v, ok := matchPrefix(trimmed, "REVISED_DESCRIPTION:"); ok {
			description = append(description, strings.TrimSpace(v))
			curField = "description"
			continue
		}
		// Otherwise it's a continuation of the current multi-line field.
		switch curField {
		case "rationale":
			rationale = append(rationale, trimmed)
		case "description":
			description = append(description, trimmed)
		}
	}

	result.Accepted = (decisionStr == "ACCEPTED")
	result.Severity = parseSeverity(severityStr)
	result.Rationale = strings.TrimSpace(strings.Join(rationale, " "))
	result.Description = strings.TrimSpace(strings.Join(description, " "))

	// Safety net: if we got nothing useful, treat as a rejection.
	if decisionStr == "" && severityStr == "" && result.Rationale == "" {
		result.Accepted = false
		result.Rationale = "unparseable LLM output: " + truncate(raw, 200)
	}
	return result
}

// matchPrefix returns (value, true) if line starts with prefix
// (case-insensitive). value is the substring after the prefix.
func matchPrefix(line, prefix string) (string, bool) {
	if len(line) < len(prefix) {
		return "", false
	}
	if !strings.EqualFold(line[:len(prefix)], prefix) {
		return "", false
	}
	return line[len(prefix):], true
}

func parseSeverity(s string) findings.Severity {
	switch s {
	case "CRITICAL":
		return findings.SeverityCritical
	case "HIGH":
		return findings.SeverityHigh
	case "MEDIUM":
		return findings.SeverityMedium
	case "LOW":
		return findings.SeverityLow
	case "INFO":
		return findings.SeverityInfo
	}
	return findings.SeverityMedium // fallback — explicit unknown
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
