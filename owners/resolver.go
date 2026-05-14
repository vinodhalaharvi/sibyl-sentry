// Package owners resolves a finding to a responsible team or person.
//
// The resolver reads a JSON config (see config/owners.json in the fixtures
// repo) with two kinds of rules: path-prefix rules (for code-based findings)
// and owner-email rules (for API-based findings like stale OAuth grants).
// A fallback project is used if nothing matches.
package owners

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

// Assignment is the outcome of resolution.
type Assignment struct {
	JiraProject string `json:"jira_project"`
	Assignee    string `json:"assignee"`
	TeamChannel string `json:"team_channel,omitempty"`
}

// Resolver routes findings to assignments.
type Resolver struct {
	pathRules     []pathRule
	emailRules    map[string]Assignment
	fallback      Assignment
}

type configFile struct {
	Rules    []configRule              `json:"rules"`
	ByOwner  map[string]configByOwner  `json:"by_owner_email"`
	Fallback configFallback            `json:"fallback"`
}

type configRule struct {
	Match struct {
		PathPrefix string `json:"path_prefix"`
	} `json:"match"`
	JiraProject     string `json:"jira_project"`
	DefaultAssignee string `json:"default_assignee"`
	TeamChannel     string `json:"team_channel"`
}

type configByOwner struct {
	JiraProject string `json:"jira_project"`
	Assignee    string `json:"assignee"`
}

type configFallback struct {
	JiraProject string `json:"jira_project"`
	Assignee    string `json:"assignee"`
	TeamChannel string `json:"team_channel"`
}

type pathRule struct {
	prefix     string
	assignment Assignment
}

// Load reads a resolver from a config file (typically config/owners.json).
func Load(path string) (*Resolver, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("owners.Load: %w", err)
	}
	var cfg configFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("owners.Load: parse: %w", err)
	}
	if cfg.Fallback.JiraProject == "" {
		return nil, errors.New("owners.Load: fallback project required")
	}

	r := &Resolver{
		fallback: Assignment{
			JiraProject: cfg.Fallback.JiraProject,
			Assignee:    cfg.Fallback.Assignee,
			TeamChannel: cfg.Fallback.TeamChannel,
		},
		emailRules: make(map[string]Assignment, len(cfg.ByOwner)),
	}
	for _, rule := range cfg.Rules {
		r.pathRules = append(r.pathRules, pathRule{
			prefix: rule.Match.PathPrefix,
			assignment: Assignment{
				JiraProject: rule.JiraProject,
				Assignee:    rule.DefaultAssignee,
				TeamChannel: rule.TeamChannel,
			},
		})
	}
	for email, by := range cfg.ByOwner {
		r.emailRules[email] = Assignment{
			JiraProject: by.JiraProject,
			Assignee:    by.Assignee,
		}
	}
	return r, nil
}

// Resolve maps a finding to a Jira assignment using its OwnerHint.
// Resolution order:
//  1. If OwnerHint looks like an email and matches by_owner_email, use that.
//  2. If OwnerHint starts with a configured path prefix, use that rule.
//  3. Fall back to the configured fallback project.
func (r *Resolver) Resolve(f findings.Finding) Assignment {
	hint := f.OwnerHint
	if hint == "" {
		return r.fallback
	}
	// Email match: contains '@' and is in the email map.
	if strings.Contains(hint, "@") {
		if a, ok := r.emailRules[hint]; ok {
			return a
		}
	}
	// Path-prefix match: longest prefix wins.
	var best *pathRule
	var bestLen int
	for i := range r.pathRules {
		pr := &r.pathRules[i]
		if strings.HasPrefix(hint, pr.prefix) && len(pr.prefix) > bestLen {
			best = pr
			bestLen = len(pr.prefix)
		}
	}
	if best != nil {
		return best.assignment
	}
	return r.fallback
}
