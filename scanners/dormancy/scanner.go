// Package dormancy implements the dormant-service-account scanner. For
// each IAM user (humans and service accounts), it inspects access keys
// and reports any user with Active credentials whose LastUsedDate is
// past the dormancy threshold.
//
// The Critic should reject findings that don't include the actual
// last-used date and the count of dormant keys — concrete evidence,
// not "looks dormant."
package dormancy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/aws"
	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

const ActivityName = "dormancy.ScanIAM"

// ScanInput is the activity input.
type ScanInput struct {
	AWSBaseURL string
	AWSToken   string

	// DormancyThreshold defaults to 180 days.
	DormancyThreshold time.Duration
}

// ScanOutput is the activity output.
type ScanOutput struct {
	Findings       []findings.Finding
	UsersReviewed  int
	KeysReviewed   int
}

// ScanIAM walks IAM users and their access keys; flags users with any
// Active key past the dormancy threshold.
func ScanIAM(ctx context.Context, in ScanInput) (*ScanOutput, error) {
	if in.AWSBaseURL == "" {
		return nil, errors.New("dormancy.ScanIAM: AWSBaseURL required")
	}
	if in.AWSToken == "" {
		return nil, errors.New("dormancy.ScanIAM: AWSToken required")
	}
	threshold := in.DormancyThreshold
	if threshold == 0 {
		threshold = 180 * 24 * time.Hour
	}

	client := aws.New(in.AWSBaseURL, in.AWSToken)

	users, err := client.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("dormancy.ScanIAM: list users: %w", err)
	}

	out := &ScanOutput{UsersReviewed: len(users)}
	now := time.Now().UTC()

	for _, u := range users {
		keys, err := client.ListAccessKeys(ctx, u.UserName)
		if err != nil {
			// Skip individual user on fetch failure.
			continue
		}
		out.KeysReviewed += len(keys)

		var dormantKeys []aws.AccessKey
		var maxIdle time.Duration
		for _, k := range keys {
			if k.Status != "Active" {
				continue
			}
			if k.LastUsedDate.IsZero() {
				continue
			}
			idle := now.Sub(k.LastUsedDate)
			if idle >= threshold {
				dormantKeys = append(dormantKeys, k)
				if idle > maxIdle {
					maxIdle = idle
				}
			}
		}
		if len(dormantKeys) == 0 {
			continue
		}

		days := int(maxIdle.Hours() / 24)
		months := days / 30

		evidence := []findings.Evidence{
			{
				Kind:        "api_field",
				Description: "AWS IAM user (ListUsers)",
				Location:    fmt.Sprintf("aws:iam/users/%s.Arn", u.UserName),
				Snippet:     u.Arn,
			},
		}
		for _, k := range dormantKeys {
			evidence = append(evidence, findings.Evidence{
				Kind:        "api_field",
				Description: fmt.Sprintf("dormant Active access key (last used %s, ~%d months ago)",
					k.LastUsedDate.Format("2006-01-02"),
					int(now.Sub(k.LastUsedDate).Hours()/24/30)),
				Location:    fmt.Sprintf("aws:iam/users/%s/access-keys/%s", u.UserName, k.AccessKeyID),
				Snippet:     fmt.Sprintf("AccessKeyId=%s Status=Active LastUsedService=%s",
					k.AccessKeyID, k.LastUsedService),
			})
		}

		out.Findings = append(out.Findings, findings.Finding{
			ID:       "dormant-iam-" + u.UserName,
			Category: findings.CategoryDormantAccount,
			Severity: severityForIdle(maxIdle, len(dormantKeys)),
			Title: fmt.Sprintf(
				"IAM user %s has %d dormant active key(s), last used ~%d months ago",
				u.UserName, len(dormantKeys), months,
			),
			Description: fmt.Sprintf(
				"User %s (%s) has %d Active access key(s) that have not been "+
					"used in %d+ days. Active dormant credentials are a "+
					"latent risk — they can be exfiltrated and used without "+
					"raising alarms because no recent activity establishes a "+
					"normal baseline. Recommend deactivation or rotation.",
				u.UserName, u.Arn, len(dormantKeys), days,
			),
			Evidence:     evidence,
			OwnerHint:    u.OwnerEmail(),
			DiscoveredAt: time.Now().UTC(),
			ScannerID:    "dormancy",
		})
	}
	return out, nil
}

// severityForIdle applies the multiplication formula:
//   grant = HIGH (IAM keys carry real cloud authority)
//   lifetime = until rotated
//   revocability = manual; rotation can break things
// So the floor is HIGH; we add multiplier for multiple dormant keys
// (more keys means more surface) and for very old keys (rotation has
// drifted further from any controlled cadence).
func severityForIdle(idle time.Duration, dormantKeyCount int) findings.Severity {
	months := idle.Hours() / 24 / 30
	if months >= 24 || dormantKeyCount >= 2 {
		return findings.SeverityCritical
	}
	if months >= 6 {
		return findings.SeverityHigh
	}
	return findings.SeverityMedium
}
