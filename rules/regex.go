// Package rules defines the secret-detection patterns Sentry uses.
//
// Two scanners consume these:
//
//   - scanners/regex: the default, pure-Go scanner. Uses RegexRules directly.
//   - scanners/yara: the libyara-backed scanner (build tag: yara). Loads
//     the embedded .yar files from rules/yara/. Those .yar files express
//     the same intent as RegexRules but in YARA syntax for richer matching
//     (e.g. condition combinators, byte-level patterns).
//
// Both produce findings of category SecretExposure.
package rules

import "regexp"

// RegexRule is a single secret-detection pattern.
type RegexRule struct {
	// ID is a stable identifier (e.g. "aws_access_key").
	ID string

	// Description is what this rule detects, used in finding descriptions.
	Description string

	// Pattern is the compiled regex. Use raw strings; case-sensitivity should
	// match the underlying secret format.
	Pattern *regexp.Regexp

	// MinEntropy, if > 0, requires the match to have at least this Shannon
	// entropy (bits) to reduce false positives. 0 disables the check.
	MinEntropy float64
}

// RegexRules is the curated default rule set. Tuned for the fixture repo
// and common cloud/SaaS secret formats. Extend by adding entries here.
var RegexRules = []RegexRule{
	{
		ID:          "aws_access_key",
		Description: "AWS access key ID",
		// AKIA + 16 uppercase alphanumerics, anchored on word boundaries.
		Pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		ID:          "aws_secret_key",
		Description: "AWS secret access key",
		// 40 chars of base64-ish alphabet. Easy to false-positive on; pair
		// with the access-key rule for higher confidence in the Critic.
		Pattern:    regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`),
		MinEntropy: 4.0,
	},
	{
		ID:          "slack_webhook",
		Description: "Slack incoming webhook URL",
		Pattern:     regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}`),
	},
	{
		ID:          "slack_token",
		Description: "Slack API token",
		Pattern:     regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
	},
	{
		ID:          "github_pat",
		Description: "GitHub personal access token",
		Pattern:     regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
	},
	{
		ID:          "private_key_pem",
		Description: "PEM-encoded private key block header",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----`),
	},
	{
		ID:          "gcp_service_account",
		Description: "GCP service account JSON marker",
		Pattern:     regexp.MustCompile(`"type"\s*:\s*"service_account"`),
	},
}
