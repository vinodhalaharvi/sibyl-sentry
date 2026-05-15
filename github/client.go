// Package github is a thin HTTP client for GitHub's REST API (mock or
// real). The same calls work against both; production would point at
// https://api.github.com and use a real personal access token.
package github

import (
	"context"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/internal/vendorhttp"
)

// Client is the typed GitHub client.
type Client struct {
	*vendorhttp.Base
}

// New constructs a GitHub client.
func New(baseURL, token string) *Client {
	return &Client{
		Base: vendorhttp.NewBase(baseURL, "Bearer "+token, "github", 30*time.Second),
	}
}

// --- Response types ---

// Org is GET /orgs/{org}.
type Org struct {
	Login                       string `json:"login"`
	ID                          int    `json:"id"`
	Description                 string `json:"description"`
	Name                        string `json:"name"`
	Company                     string `json:"company"`
	TwoFactorRequirementEnabled bool   `json:"two_factor_requirement_enabled"`
	MembersCount                int    `json:"members_count"`
}

// Member is one entry in GET /orgs/{org}/members.
type Member struct {
	Login      string `json:"login"`
	ID         int    `json:"id"`
	Type       string `json:"type"` // "User" or "Bot"
	SiteAdmin  bool   `json:"site_admin"`
	// Mock convenience: the SAML SSO link to Okta. Real GitHub exposes
	// this through the SAML SSO API as a separate endpoint.
	OktaUserID string `json:"_okta_user_id,omitempty"`
	Role       string `json:"_role,omitempty"`
}

// Repo is one entry in GET /orgs/{org}/repos.
type Repo struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// Collaborator is one entry in GET /repos/{owner}/{repo}/collaborators.
type Collaborator struct {
	Login       string      `json:"login"`
	ID          int         `json:"id"`
	Permissions Permissions `json:"permissions"`
	OktaUserID  string      `json:"_okta_user_id,omitempty"`
}

// Permissions captures the access level a collaborator has.
type Permissions struct {
	Admin bool `json:"admin"`
	Push  bool `json:"push"`
	Pull  bool `json:"pull"`
}

// Team is one entry in GET /orgs/{org}/teams.
type Team struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	// Mock convenience: the Okta group this team is SCIM-synced from.
	OktaGroupID string `json:"_okta_group_id,omitempty"`
}

// TeamMember is one entry in GET /orgs/{org}/teams/{slug}/members.
// Same shape as Member but kept separate for type clarity.
type TeamMember = Member

// --- Methods ---

// GetOrg fetches org details.
func (c *Client) GetOrg(ctx context.Context, org string) (*Org, error) {
	var out Org
	if err := c.GetJSON(ctx, "orgs/"+org, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOrgMembers returns all members of an organization.
func (c *Client) ListOrgMembers(ctx context.Context, org string) ([]Member, error) {
	var out []Member
	if err := c.GetJSON(ctx, "orgs/"+org+"/members", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListOrgRepos returns all repos in an organization.
func (c *Client) ListOrgRepos(ctx context.Context, org string) ([]Repo, error) {
	var out []Repo
	if err := c.GetJSON(ctx, "orgs/"+org+"/repos", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListRepoCollaborators returns who has push/admin/pull access to a repo.
// This is the lateral-movement bridge: anyone with push access to a repo
// containing leaked secrets has those secrets in their effective blast
// radius even if Okta has no idea.
func (c *Client) ListRepoCollaborators(ctx context.Context, owner, repo string) ([]Collaborator, error) {
	var out []Collaborator
	if err := c.GetJSON(ctx, "repos/"+owner+"/"+repo+"/collaborators", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListOrgTeams returns all teams in an organization.
func (c *Client) ListOrgTeams(ctx context.Context, org string) ([]Team, error) {
	var out []Team
	if err := c.GetJSON(ctx, "orgs/"+org+"/teams", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListTeamMembers returns members of one team.
func (c *Client) ListTeamMembers(ctx context.Context, org, teamSlug string) ([]TeamMember, error) {
	var out []TeamMember
	if err := c.GetJSON(ctx, "orgs/"+org+"/teams/"+teamSlug+"/members", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- Helpers ---

// HasPush reports whether a collaborator can push to the repo. The
// blast-radius scanner uses this to filter to write-access — read-only
// access doesn't usually create a credential-leak risk by itself.
func (c Collaborator) HasPush() bool {
	return c.Permissions.Push || c.Permissions.Admin
}
