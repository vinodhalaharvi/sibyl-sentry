// Package oauth implements the stale-OAuth-grant scanner. It reads
// oauth-clients.json (in production: the Okta API) and flags clients
// whose last_used timestamp is beyond the freshness threshold while
// the client is still active.
//
// The Critic should reject findings that don't include the actual
// last_used date and a duration since — i.e. concrete staleness evidence.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

const ActivityName = "oauth.ScanStale"

type Client struct {
	ClientID  string    `json:"client_id"`
	Name      string    `json:"name"`
	Created   time.Time `json:"created"`
	LastUsed  time.Time `json:"last_used"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
	Owner     string    `json:"owner"`
}

type clientsFile struct {
	AsOf    time.Time `json:"as_of"`
	Clients []Client  `json:"clients"`
}

type ScanInput struct {
	// InventoryPath is the JSON file to read (config/oauth-clients.json
	// in the fixtures repo). In production this is replaced by an Okta
	// API call activity.
	InventoryPath string

	// StalenessThreshold is how long since last_used qualifies as stale.
	// Default 365 days. The Critic should also rule out clients that
	// were merely *recently used* but with edge cases (e.g. 65 days
	// might be a quarterly script — not stale).
	StalenessThreshold time.Duration
}

type ScanOutput struct {
	Findings        []findings.Finding
	ClientsReviewed int
}

func ScanStale(_ context.Context, in ScanInput) (*ScanOutput, error) {
	if in.InventoryPath == "" {
		return nil, errors.New("oauth.ScanStale: InventoryPath required")
	}
	threshold := in.StalenessThreshold
	if threshold == 0 {
		threshold = 365 * 24 * time.Hour
	}

	data, err := os.ReadFile(in.InventoryPath)
	if err != nil {
		return nil, fmt.Errorf("oauth.ScanStale: read: %w", err)
	}
	var file clientsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("oauth.ScanStale: parse: %w", err)
	}

	asOf := file.AsOf
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	out := &ScanOutput{ClientsReviewed: len(file.Clients)}
	for _, c := range file.Clients {
		if c.Status != "active" {
			continue
		}
		if c.LastUsed.IsZero() {
			continue
		}
		idle := asOf.Sub(c.LastUsed)
		if idle < threshold {
			continue
		}
		days := int(idle.Hours() / 24)
		out.Findings = append(out.Findings, findings.Finding{
			ID:       "stale-oauth-" + c.ClientID,
			Category: findings.CategoryStaleOAuth,
			Severity: severityForIdle(idle),
			Title: fmt.Sprintf(
				"OAuth client %s (%q) unused for %d days",
				c.ClientID, c.Name, days,
			),
			Description: fmt.Sprintf(
				"Client %s (%q) was last used on %s — %d days ago — but "+
					"is still active and not expired until %s. Stale active "+
					"clients are an unnecessary identity-attack surface. "+
					"Recommend revocation or owner re-attestation.",
				c.ClientID, c.Name,
				c.LastUsed.Format("2006-01-02"), days,
				c.ExpiresAt.Format("2006-01-02"),
			),
			Evidence: []findings.Evidence{
				{
					Kind:        "api_field",
					Description: "last_used timestamp",
					Location:    fmt.Sprintf("oauth-clients.json:%s.last_used", c.ClientID),
					Snippet:     c.LastUsed.Format(time.RFC3339),
				},
				{
					Kind:        "api_field",
					Description: "status field",
					Location:    fmt.Sprintf("oauth-clients.json:%s.status", c.ClientID),
					Snippet:     c.Status,
				},
			},
			OwnerHint:    c.Owner,
			DiscoveredAt: time.Now().UTC(),
			ScannerID:    "oauth",
		})
	}
	return out, nil
}

func severityForIdle(idle time.Duration) findings.Severity {
	days := idle.Hours() / 24
	switch {
	case days > 730: // >2 years
		return findings.SeverityCritical
	case days > 365: // >1 year
		return findings.SeverityHigh
	default:
		return findings.SeverityMedium
	}
}
