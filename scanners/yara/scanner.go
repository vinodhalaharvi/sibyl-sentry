//go:build yara

// Package yara implements the libyara-backed secret scanner. Build with:
//
//	go build -tags yara ./...
//
// Requires libyara 4.3+ and pkg-config installed. On macOS:
//
//	brew install yara pkg-config
//
// On Debian/Ubuntu:
//
//	apt install libyara-dev pkg-config
//
// The activity signature matches scanners/regex.Scan exactly, so the
// audit workflow can dispatch to either based on the build configuration.
package yara

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"go.temporal.io/sdk/activity"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

const ActivityName = "yara.Scan"

// ScanInput mirrors regex.ScanInput.
type ScanInput struct {
	TargetPath   string
	ScanHistory  bool
	MaxFileBytes int64
	SkipPatterns []string

	// RulesSource is YARA rule source. If empty, the default embedded
	// rules are used (see rules/yara/*.yar; loaded by initRules()).
	RulesSource string
}

type ScanOutput struct {
	Findings     []findings.Finding
	FilesScanned int
}

// Scan compiles the rules once, then walks the target tree applying them
// to each file via yara.Rules.ScanMem. History scanning is left as TODO —
// for the hackathon demo the historical-exposure finding is well-served
// by the regex scanner's git-log path; this YARA scanner focuses on the
// working tree where libyara's richer matching shines.
func Scan(ctx context.Context, in ScanInput) (*ScanOutput, error) {
	if in.TargetPath == "" {
		return nil, errors.New("yara.Scan: TargetPath required")
	}
	source := in.RulesSource
	if source == "" {
		source = defaultRules
	}
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara.NewCompiler: %w", err)
	}
	if err := compiler.AddString(source, "sentry"); err != nil {
		return nil, fmt.Errorf("yara.Compiler.AddString: %w", err)
	}
	rs, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("yara.Compiler.GetRules: %w", err)
	}

	out := &ScanOutput{}
	skip := defaultSkipPatterns
	if len(in.SkipPatterns) > 0 {
		skip = in.SkipPatterns
	}

	walkErr := filepath.WalkDir(in.TargetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(path, skip) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipFile(path, skip) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if in.MaxFileBytes > 0 && info.Size() > in.MaxFileBytes {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		out.FilesScanned++
		if out.FilesScanned%50 == 0 {
			if activity.IsActivity(ctx) {
				activity.RecordHeartbeat(ctx, out.FilesScanned)
			}
		}

		var matches yara.MatchRules
		if err := rs.ScanMem(data, 0, 5*time.Second, &matches); err != nil {
			if activity.IsActivity(ctx) {
				activity.GetLogger(ctx).Warn("yara scan error", "path", path, "err", err)
			}
			return nil
		}
		rel, _ := filepath.Rel(in.TargetPath, path)
		for _, m := range matches {
			out.Findings = append(out.Findings, matchToFinding(m, rel, data))
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("yara.Scan: walk: %w", walkErr)
	}

	return out, nil
}

func matchToFinding(m yara.MatchRule, path string, data []byte) findings.Finding {
	// Pick the first string match for the evidence location.
	var loc, snippet string
	if len(m.Strings) > 0 {
		s := m.Strings[0]
		line := lineOfOffset(data, int(s.Offset))
		loc = fmt.Sprintf("%s:%d", path, line)
		snippet = truncate(string(s.Data), 120)
	} else {
		loc = path
	}
	return findings.Finding{
		ID:       findingID(m.Rule, loc, snippet),
		Category: findings.CategorySecretExposure,
		Severity: severityFor(m.Rule),
		Title:    fmt.Sprintf("YARA rule %s matched in %s", m.Rule, path),
		Description: fmt.Sprintf(
			"YARA rule %q (namespace %s) matched at %s. Tags: %v.",
			m.Rule, m.Namespace, loc, m.Tags,
		),
		Evidence: []findings.Evidence{{
			Kind:        "yara_match",
			Description: fmt.Sprintf("Rule %s, namespace %s", m.Rule, m.Namespace),
			Location:    loc,
			Snippet:     snippet,
		}},
		OwnerHint:    path,
		DiscoveredAt: time.Now().UTC(),
		ScannerID:    "yara",
	}
}

// Shared helpers (duplicated from regex scanner; small enough to not warrant
// a third package, and keeps build-tag isolation clean).

var defaultSkipPatterns = []string{
	"/.git/", "/node_modules/", "/vendor/", "/.venv/", "__pycache__",
	".min.js", ".min.css",
}

func shouldSkipDir(path string, skip []string) bool {
	for _, s := range skip {
		if strings.Contains(path+"/", s) {
			return true
		}
	}
	return false
}

func shouldSkipFile(path string, skip []string) bool {
	for _, s := range skip {
		if strings.Contains(path, s) {
			return true
		}
	}
	return false
}

func lineOfOffset(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if data[i] == '\n' {
			line++
		}
	}
	return line
}

func findingID(rule, location, snippet string) string {
	h := sha256.Sum256([]byte(rule + "|" + location + "|" + snippet))
	return rule + "-" + hex.EncodeToString(h[:6])
}

func severityFor(rule string) findings.Severity {
	switch rule {
	case "aws_access_key", "aws_secret_key", "github_pat", "private_key_pem":
		return findings.SeverityHigh
	case "slack_webhook", "slack_token":
		return findings.SeverityMedium
	default:
		return findings.SeverityMedium
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// defaultRules is a curated YARA rule set matching the same intent as
// rules.RegexRules but expressed in YARA syntax. Embedded as a string to
// keep the build simple for the hackathon; can be moved to embed.FS later.
const defaultRules = `
rule aws_access_key {
    meta:
        description = "AWS access key ID"
        severity = "high"
    strings:
        $key = /\bAKIA[0-9A-Z]{16}\b/
    condition:
        $key
}

rule aws_secret_key {
    meta:
        description = "AWS secret access key (paired check recommended)"
        severity = "high"
    strings:
        $sec = /\b[A-Za-z0-9\/+=]{40}\b/
    condition:
        $sec
}

rule slack_webhook {
    meta:
        description = "Slack incoming webhook URL"
        severity = "medium"
    strings:
        $url = /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,}/
    condition:
        $url
}

rule github_pat {
    meta:
        description = "GitHub personal access token"
        severity = "high"
    strings:
        $tok = /\bghp_[A-Za-z0-9]{36}\b/
    condition:
        $tok
}

rule private_key_pem {
    meta:
        description = "PEM-encoded private key block header"
        severity = "high"
    strings:
        $hdr = "-----BEGIN"
        $key = "PRIVATE KEY-----"
    condition:
        $hdr and $key
}
`
