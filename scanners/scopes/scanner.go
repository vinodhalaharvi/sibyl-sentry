// Package scopes implements the over-privilege scanner. For each OAuth
// client in the Okta tenant, it diffs granted scopes against scopes
// actually used in the last 90 days. Any granted scope not used in the
// window is reported.
//
// The Critic should reject findings that don't name the specific unused
// scopes — generic "over-privileged" claims aren't actionable.
package scopes

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
	"github.com/vinodhalaharvi/sibyl-sentry/okta"
)

const ActivityName = "scopes.ScanOverPrivilege"

// ScanInput is the activity input.
type ScanInput struct {
	OktaBaseURL string
	OktaToken   string

	// UsageWindowDays defaults to 90.
	UsageWindowDays int
}

// ScanOutput is the activity output.
type ScanOutput struct {
	Findings        []findings.Finding
	ClientsReviewed int
}

// ScanOverPrivilege walks every OAuth client and produces a finding for
// each one with granted scopes that haven't been exercised.
func ScanOverPrivilege(ctx context.Context, in ScanInput) (*ScanOutput, error) {
	const nodeID = "scopes"
	const label = "Over-Privilege"
	started := time.Now()
	emitter := sibylproxy.EmitterForActivity(ctx)
	emitter.Emit(sibylproxy.NewNodeStarted("", nodeID, label))

	if in.OktaBaseURL == "" {
		err := errors.New("scopes.ScanOverPrivilege: OktaBaseURL required")
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}
	if in.OktaToken == "" {
		err := errors.New("scopes.ScanOverPrivilege: OktaToken required")
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}

	client := okta.New(in.OktaBaseURL, in.OktaToken)

	apps, err := client.ListApps(ctx)
	if err != nil {
		err = fmt.Errorf("scopes.ScanOverPrivilege: list apps: %w", err)
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}

	out := &ScanOutput{ClientsReviewed: len(apps)}

	for _, a := range apps {
		// Fetch detail — granted scopes live there (and used-scopes in the
		// mock; in real Okta we'd pull these from the System Log).
		detail, err := client.GetApp(ctx, a.ID)
		if err != nil {
			// Skip on individual fetch failure; don't fail the whole scan.
			continue
		}

		unused := setDiff(detail.GrantedScopes, detail.ScopesUsed90D)
		if len(unused) == 0 {
			continue
		}

		// Sort for deterministic output (important for stable finding IDs
		// and for the Critic to evaluate consistently).
		sort.Strings(unused)

		out.Findings = append(out.Findings, findings.Finding{
			ID:       "over-priv-" + a.ID,
			Category: findings.CategoryOverPrivilege,
			Severity: severityForUnused(len(unused), len(detail.GrantedScopes)),
			Title: fmt.Sprintf(
				"OAuth client %s (%q) has %d unused scope(s)",
				a.ID, a.Label, len(unused),
			),
			Description: fmt.Sprintf(
				"Client %s (%q) was granted %d scopes but only used %d in "+
					"the last %d days. Unused scopes: %s. Recommend reducing "+
					"the grant to only what's actively used.",
				a.ID, a.Label,
				len(detail.GrantedScopes),
				len(detail.ScopesUsed90D),
				usageWindow(in.UsageWindowDays),
				strings.Join(unused, ", "),
			),
			Evidence: []findings.Evidence{
				{
					Kind:        "api_field",
					Description: "granted scopes (Okta app detail)",
					Location:    fmt.Sprintf("okta:apps/%s.grantedScopes", a.ID),
					Snippet:     strings.Join(detail.GrantedScopes, ", "),
				},
				{
					Kind:        "api_field",
					Description: fmt.Sprintf("scopes used in last %d days (Okta System Log)", usageWindow(in.UsageWindowDays)),
					Location:    fmt.Sprintf("okta:apps/%s.scopesUsed", a.ID),
					Snippet:     strings.Join(detail.ScopesUsed90D, ", "),
				},
				{
					Kind:        "computed",
					Description: "unused scopes (granted ∖ used)",
					Location:    fmt.Sprintf("okta:apps/%s", a.ID),
					Snippet:     strings.Join(unused, ", "),
				},
			},
			OwnerHint:    detail.Owner,
			DiscoveredAt: time.Now().UTC(),
			ScannerID:    "scopes",
		})
	}
	emitter.Emit(sibylproxy.NewNodeCompleted("", nodeID, label,
		map[string]interface{}{
			"clients_reviewed": out.ClientsReviewed,
			"findings_count":   len(out.Findings),
		},
		time.Since(started),
	))
	return out, nil
}

// setDiff returns elements in a not present in b. Case-sensitive on
// scope names (Okta scopes are case-sensitive).
func setDiff(a, b []string) []string {
	have := make(map[string]struct{}, len(b))
	for _, s := range b {
		have[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := have[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

// severityForUnused maps "fraction of grants that are unused" to a
// severity. A handful of unused scopes is informational; majority unused
// is a clear over-grant.
func severityForUnused(unused, granted int) findings.Severity {
	if granted == 0 {
		return findings.SeverityLow
	}
	frac := float64(unused) / float64(granted)
	switch {
	case frac >= 0.66:
		return findings.SeverityHigh
	case frac >= 0.33:
		return findings.SeverityMedium
	default:
		return findings.SeverityLow
	}
}

func usageWindow(days int) int {
	if days == 0 {
		return 90
	}
	return days
}
