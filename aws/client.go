// Package aws is a thin HTTP client for the AWS IAM-shaped mock surface.
// In production, Sentry would use the AWS SDK and SigV4 signing; this
// package replaces that with simple JSON GETs against the mock for the
// hackathon demo. The data model and method names match the SDK so
// swapping to real AWS is mostly a re-implementation of the transport.
package aws

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/internal/vendorhttp"
)

// Client is the typed AWS IAM client.
type Client struct {
	*vendorhttp.Base
}

// New constructs an AWS IAM mock client.
func New(baseURL, token string) *Client {
	return &Client{
		Base: vendorhttp.NewBase(baseURL, "AWS4-HMAC-SHA256 "+token, "aws", 30*time.Second),
	}
}

// --- Response types ---

// User is one entry in GET /iam/users.
type User struct {
	UserName         string    `json:"UserName"`
	UserID           string    `json:"UserId"`
	Arn              string    `json:"Arn"`
	CreateDate       time.Time `json:"CreateDate"`
	PasswordLastUsed *time.Time `json:"PasswordLastUsed"`
	Tags             []Tag     `json:"Tags"`
}

// UsersResponse wraps the User array (matches AWS's response envelope).
type UsersResponse struct {
	Users []User `json:"Users"`
}

// Tag is one AWS resource tag.
type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// AccessKey is one entry in GET /iam/users/{name}/access-keys.
type AccessKey struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	Status          string    `json:"Status"` // "Active" or "Inactive"
	CreateDate      time.Time `json:"CreateDate"`
	LastUsedDate    time.Time `json:"LastUsedDate"`
	LastUsedService string    `json:"LastUsedService"`
	LastUsedRegion  string    `json:"LastUsedRegion"`
}

// AccessKeysResponse wraps the AccessKey array.
type AccessKeysResponse struct {
	UserName          string      `json:"UserName"`
	AccessKeyMetadata []AccessKey `json:"AccessKeyMetadata"`
}

// Role is one entry in GET /iam/roles.
type Role struct {
	RoleName                 string                 `json:"RoleName"`
	RoleID                   string                 `json:"RoleId"`
	Arn                      string                 `json:"Arn"`
	CreateDate               time.Time              `json:"CreateDate"`
	AssumeRolePolicyDocument map[string]interface{} `json:"AssumeRolePolicyDocument"`
	// Mock-only convenience: which Okta groups can assume this role via SAML.
	AssumableByOktaGroups []string `json:"_assumable_by_okta_groups,omitempty"`
}

// RolesResponse wraps the Role array.
type RolesResponse struct {
	Roles []Role `json:"Roles"`
}

// AttachedPolicy is one entry in GET /iam/roles/{name}/policies.
type AttachedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// RolePoliciesResponse wraps the AttachedPolicy array.
type RolePoliciesResponse struct {
	RoleName         string           `json:"RoleName"`
	AttachedPolicies []AttachedPolicy `json:"AttachedPolicies"`
}

// PolicyDocument is the response from GET /iam/policies/{arn}.
type PolicyDocument struct {
	PolicyName     string                 `json:"PolicyName"`
	Arn            string                 `json:"Arn"`
	PolicyDocument json.RawMessage        `json:"PolicyDocument"`
}

// --- Methods ---

// ListUsers returns all IAM users (humans + service accounts).
// The dormancy scanner iterates this list to find candidates.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out UsersResponse
	if err := c.GetJSON(ctx, "iam/users", &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

// ListAccessKeys returns the access keys for one user. The dormancy
// scanner pairs this with ListUsers to evaluate per-key last-used time.
func (c *Client) ListAccessKeys(ctx context.Context, userName string) ([]AccessKey, error) {
	var out AccessKeysResponse
	if err := c.GetJSON(ctx, "iam/users/"+userName+"/access-keys", &out); err != nil {
		return nil, err
	}
	return out.AccessKeyMetadata, nil
}

// ListRoles returns all IAM roles. Used by the blast-radius scanner to
// determine which roles an Okta-federated user can assume.
func (c *Client) ListRoles(ctx context.Context) ([]Role, error) {
	var out RolesResponse
	if err := c.GetJSON(ctx, "iam/roles", &out); err != nil {
		return nil, err
	}
	return out.Roles, nil
}

// ListRolePolicies returns policies attached to one role.
func (c *Client) ListRolePolicies(ctx context.Context, roleName string) ([]AttachedPolicy, error) {
	var out RolePoliciesResponse
	if err := c.GetJSON(ctx, "iam/roles/"+roleName+"/policies", &out); err != nil {
		return nil, err
	}
	return out.AttachedPolicies, nil
}

// GetPolicy fetches a policy document by ARN. The mock URL-decodes the
// path and maps the ARN to its on-disk filename; here we just pass the
// ARN through URL-encoded.
func (c *Client) GetPolicy(ctx context.Context, arn string) (*PolicyDocument, error) {
	var out PolicyDocument
	encoded := url.PathEscape(arn)
	if err := c.GetJSON(ctx, "iam/policies/"+encoded, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Helpers exposed for scanners ---

// IsHuman reports whether an IAM user looks human (has password-last-used
// in profile) vs. a service account. Heuristic — production code would
// rely on tags or naming conventions.
func (u User) IsHuman() bool {
	return u.PasswordLastUsed != nil
}

// OwnerEmail returns the value of the "owner" tag if present, "" otherwise.
// Used to route findings to Jira via the owners resolver.
func (u User) OwnerEmail() string {
	for _, t := range u.Tags {
		if strings.EqualFold(t.Key, "owner") {
			return t.Value
		}
	}
	return ""
}
