// Package oauth implements the stale-OAuth-grant scanner. It calls the
// Okta admin API to enumerate OAuth clients and flags those whose
// last_used timestamp is beyond the freshness threshold while the
// client is still active.
//
// The Critic should reject findings that don't include the actual
// last_used date and a duration since — i.e. concrete staleness evidence.
package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
	"github.com/vinodhalaharvi/sibyl-sentry/okta"
)

const ActivityName = "oauth.ScanStale"

// ScanInput is the activity input.
type ScanInput struct {
	// OktaBaseURL is the Okta API root, e.g. "http://localhost:9001"
	// for the mock or "https://example.okta.com" for production.
	OktaBaseURL string

	// OktaToken is the SSWS token; the mock accepts any non-empty value.
	OktaToken string

	// StalenessThreshold is how long since last_used qualifies as stale.
	// Defaults to 365 days. The Critic should also rule out clients
	// that are merely *recently used* but with edge cases (e.g. 65 days
	// might be a quarterly script — not stale).
	StalenessThreshold time.Duration
}

// ScanOutput is the activity output.
type ScanOutput struct {
	Findings        []findings.Finding
	ClientsReviewed int
}

// ScanStale enumerates OAuth clients and produces a finding for each
// one that's been idle past the threshold while still active.
func ScanStale(ctx context.Context, in ScanInput) (*ScanOutput, error) {
	const nodeID = "oauth"
	const label = "Stale OAuth"
	started := time.Now()
	emitter := sibylproxy.EmitterForActivity(ctx)
	emitter.Emit(sibylproxy.NewNodeStarted("", nodeID, label))

	if in.OktaBaseURL == "" {
		err := errors.New("oauth.ScanStale: OktaBaseURL required")
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}
	if in.OktaToken == "" {
		err := errors.New("oauth.ScanStale: OktaToken required")
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}
	threshold := in.StalenessThreshold
	if threshold == 0 {
		threshold = 365 * 24 * time.Hour
	}

	client := okta.New(in.OktaBaseURL, in.OktaToken)

	apps, err := client.ListApps(ctx)
	if err != nil {
		err = fmt.Errorf("oauth.ScanStale: list apps: %w", err)
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}

	out := &ScanOutput{ClientsReviewed: len(apps)}
	now := time.Now().UTC()

	for _, a := range apps {
		if a.Status != "ACTIVE" {
			continue
		}
		if a.LastUsedMS.IsZero() {
			// No last-used info available; we'd query the System Log for
			// real Okta. Mock provides it inline so this case shouldn't
			// happen in fixtures, but handle gracefully.
			continue
		}
		idle := now.Sub(a.LastUsedMS)
		if idle < threshold {
			continue
		}
		days := int(idle.Hours() / 24)
		out.Findings = append(out.Findings, findings.Finding{
			ID:       "stale-oauth-" + a.ID,
			Category: findings.CategoryStaleOAuth,
			Severity: severityForIdle(idle),
			Title: fmt.Sprintf(
				"OAuth client %s (%q) unused for %d days",
				a.ID, a.Label, days,
			),
			Description: fmt.Sprintf(
				"Client %s (%q) was last used on %s — %d days ago — but "+
					"is still active per Okta. Stale active clients are an "+
					"unnecessary identity-attack surface. Recommend revocation "+
					"or owner re-attestation.",
				a.ID, a.Label,
				a.LastUsedMS.Format("2006-01-02"), days,
			),
			Evidence: []findings.Evidence{
				{
					Kind:        "api_field",
					Description: "Okta /api/v1/apps last_used (via _last_used_ms in mock)",
					Location:    fmt.Sprintf("okta:apps/%s.lastUsed", a.ID),
					Snippet:     a.LastUsedMS.Format(time.RFC3339),
				},
				{
					Kind:        "api_field",
					Description: "Okta /api/v1/apps status",
					Location:    fmt.Sprintf("okta:apps/%s.status", a.ID),
					Snippet:     a.Status,
				},
			},
			OwnerHint:    a.Owner,
			DiscoveredAt: time.Now().UTC(),
			ScannerID:    "oauth",
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

// severityForIdle maps "how stale" to a severity. The multiplication
// formula from our design docs:
//   grant  = HIGH (OAuth client implies API access)
//   lifetime = unbounded until revoked
//   revocability = needs admin action
// So the floor is HIGH; we escalate to CRITICAL past 2 years because at
// that point any rotation effort already missed multiple cycles.
func severityForIdle(idle time.Duration) findings.Severity {
	days := idle.Hours() / 24
	switch {
	case days > 730:
		return findings.SeverityCritical
	case days > 365:
		return findings.SeverityHigh
	default:
		return findings.SeverityMedium
	}
}
