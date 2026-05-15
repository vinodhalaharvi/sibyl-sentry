// Package okta is a thin HTTP client for Okta's admin API (mock or real).
// It exposes only the endpoints Sentry's scanners call.
//
// Construct with New(baseURL, token). For mocks:
//
//	okta.New("http://localhost:9001", "demo-token")
//
// For real Okta:
//
//	okta.New("https://example.okta.com", os.Getenv("OKTA_API_TOKEN"))
//
// The same calls work against both. The mock's auth check requires only
// presence of the "SSWS <token>" header; real Okta validates the token.
package okta

import (
	"context"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/internal/vendorhttp"
)

// Client is the typed Okta API client.
type Client struct {
	*vendorhttp.Base
}

// New constructs an Okta client. token is the bearer token; it's prefixed
// with "SSWS " to match Okta's auth scheme.
func New(baseURL, token string) *Client {
	return &Client{
		Base: vendorhttp.NewBase(baseURL, "SSWS "+token, "okta", 30*time.Second),
	}
}

// --- Response types ---
// These mirror the Okta admin API response shapes for the fields Sentry
// uses. Unknown fields are tolerated by encoding/json; we only declare
// what we read.

// User is the response from GET /api/v1/users/{id}.
type User struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	Created     time.Time `json:"created"`
	LastLogin   time.Time `json:"lastLogin"`
	LastUpdated time.Time `json:"lastUpdated"`
	Profile     Profile   `json:"profile"`
}

// Profile holds the user's identifying fields.
type Profile struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Login     string `json:"login"`
	Title     string `json:"title"`
	Department string `json:"department"`
}

// Group is one entry in GET /api/v1/users/{id}/groups or /api/v1/groups.
type Group struct {
	ID      string       `json:"id"`
	Type    string       `json:"type"`
	Profile GroupProfile `json:"profile"`
}

// GroupProfile carries the group's name and description.
type GroupProfile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// AppLink is one entry in GET /api/v1/users/{id}/appLinks — apps assigned
// directly to a user (bypassing group mediation).
type AppLink struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	AppName       string `json:"appName"`
	AppInstanceID string `json:"appInstanceId"`
	LinkURL       string `json:"linkUrl"`
	SortOrder     int    `json:"sortOrder"`
}

// GroupApp is one entry in GET /api/v1/groups/{id}/apps.
type GroupApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Label  string `json:"label"`
	Status string `json:"status"`
}

// App is one entry in GET /api/v1/apps. Note: the mock includes the
// vendor-extra fields _last_used_ms and _owner for demo convenience;
// real Okta exposes last-used via the System Log API. Sentry's scanners
// use whichever path is available.
type App struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Label        string    `json:"label"`
	Status       string    `json:"status"`
	Created      time.Time `json:"created"`
	LastUpdated  time.Time `json:"lastUpdated"`
	// Extension fields (mock convenience; not present in real Okta).
	LastUsedMS   time.Time `json:"_last_used_ms,omitempty"`
	Owner        string    `json:"_owner,omitempty"`
}

// AppDetail is GET /api/v1/apps/{id}. Adds granted-scope info on top of
// App. In real Okta, scope grants are a separate call
// (/api/v1/apps/{id}/grants); the mock merges them into the app detail
// for fixture simplicity, and the scanner accepts both shapes.
type AppDetail struct {
	App
	Settings        AppSettings `json:"settings"`
	GrantedScopes   []string    `json:"_granted_scopes"`
	ScopesUsed90D   []string    `json:"_scopes_used_90d"`
}

// AppSettings holds OAuth client configuration.
type AppSettings struct {
	OAuthClient OAuthClientSettings `json:"oauthClient"`
}

// OAuthClientSettings is the OAuth-specific subset of an app's settings.
type OAuthClientSettings struct {
	ClientURI       string   `json:"client_uri"`
	RedirectURIs    []string `json:"redirect_uris"`
	ApplicationType string   `json:"application_type"`
	GrantTypes      []string `json:"grant_types"`
}

// LogEvent is one entry in GET /api/v1/logs. The over-privilege scanner
// reads policy.evaluate_sign_on events to compute which granted scopes
// were exercised in the lookback window.
type LogEvent struct {
	UUID         string             `json:"uuid"`
	Published    time.Time          `json:"published"`
	EventType    string             `json:"eventType"`
	Actor        LogActor           `json:"actor"`
	Outcome      LogOutcome         `json:"outcome"`
	DebugContext LogDebugContext    `json:"debugContext"`
}

// LogActor identifies what initiated the event (usually an app instance).
type LogActor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// LogOutcome is the success/failure of the event.
type LogOutcome struct {
	Result string `json:"result"`
}

// LogDebugContext.DebugData.Scopes is where the consumed scopes live as
// a space-delimited string in Okta's format.
type LogDebugContext struct {
	DebugData map[string]string `json:"debugData"`
}

// --- Methods ---

// GetUser fetches a single user by ID.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	var out User
	if err := c.GetJSON(ctx, "api/v1/users/"+id, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListUserGroups returns the groups a user belongs to.
func (c *Client) ListUserGroups(ctx context.Context, userID string) ([]Group, error) {
	var out []Group
	if err := c.GetJSON(ctx, "api/v1/users/"+userID+"/groups", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListUserAppLinks returns apps assigned directly to a user.
func (c *Client) ListUserAppLinks(ctx context.Context, userID string) ([]AppLink, error) {
	var out []AppLink
	if err := c.GetJSON(ctx, "api/v1/users/"+userID+"/appLinks", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListGroups returns all groups in the org.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var out []Group
	if err := c.GetJSON(ctx, "api/v1/groups", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListGroupApps returns apps assigned to a group.
func (c *Client) ListGroupApps(ctx context.Context, groupID string) ([]GroupApp, error) {
	var out []GroupApp
	if err := c.GetJSON(ctx, "api/v1/groups/"+groupID+"/apps", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListApps returns the OAuth client / app inventory. The stale-OAuth and
// over-privilege scanners both start here.
func (c *Client) ListApps(ctx context.Context) ([]App, error) {
	var out []App
	if err := c.GetJSON(ctx, "api/v1/apps", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetApp returns one app's detail including granted scopes.
func (c *Client) GetApp(ctx context.Context, appID string) (*AppDetail, error) {
	var out AppDetail
	if err := c.GetJSON(ctx, "api/v1/apps/"+appID, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListLogs returns the system log. The mock returns all events; real
// Okta requires filter/since/until query parameters. We'll add those when
// the scanner needs to scope the window.
func (c *Client) ListLogs(ctx context.Context) ([]LogEvent, error) {
	var out []LogEvent
	if err := c.GetJSON(ctx, "api/v1/logs", &out); err != nil {
		return nil, err
	}
	return out, nil
}
