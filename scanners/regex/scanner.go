// Package regex implements a pure-Go secret scanner using regex patterns.
// It walks files in a target directory and (optionally) git history, applies
// rules from the rules package, and emits findings.
//
// This is the default secret scanner — no CGO, no libyara dependency. It is
// also the fallback when the yara build tag is not set. The YARA scanner
// (scanners/yara) produces structurally compatible findings.
package regex

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
	"github.com/vinodhalaharvi/sibyl-sentry/rules"
)

// ScanInput is the activity input.
type ScanInput struct {
	// TargetPath is the directory to scan (typically a checked-out git repo).
	TargetPath string

	// ScanHistory, if true, runs `git log -p` and applies rules to the diff.
	// This is what finds secrets that were committed and later deleted —
	// the "historical exposure" finding that's a star demo case.
	ScanHistory bool

	// MaxFileBytes caps the size of any single file scanned. 0 = no cap.
	// Useful to skip large binary blobs.
	MaxFileBytes int64

	// SkipPatterns are path substrings to skip. Defaults applied below.
	SkipPatterns []string
}

// ScanOutput is the activity output.
type ScanOutput struct {
	Findings   []findings.Finding
	FilesScanned int
	HistoryBytesScanned int64
}

// Activity is the scanner's Temporal activity. Register with name "regex.Scan".
const ActivityName = "regex.Scan"

// Scan walks TargetPath and applies the configured rules. It heartbeats
// every 50 files so Temporal knows long scans are still alive.
func Scan(ctx context.Context, in ScanInput) (*ScanOutput, error) {
	const nodeID = "secrets"
	const label = "Secrets"
	started := time.Now()
	emitter := sibylproxy.EmitterForActivity(ctx)
	emitter.Emit(sibylproxy.NewNodeStarted("", nodeID, label))

	if in.TargetPath == "" {
		err := errors.New("regex.Scan: TargetPath required")
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}
	if _, err := os.Stat(in.TargetPath); err != nil {
		err = fmt.Errorf("regex.Scan: target path: %w", err)
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}

	skip := defaultSkipPatterns
	if len(in.SkipPatterns) > 0 {
		skip = in.SkipPatterns
	}

	out := &ScanOutput{}

	// 1. Walk the working tree.
	err := filepath.WalkDir(in.TargetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable
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
			heartbeat(ctx, out.FilesScanned)
		}
		rel, _ := filepath.Rel(in.TargetPath, path)
		out.Findings = append(out.Findings, scanBytes(data, rel, "working_tree")...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("regex.Scan: walk: %w", err)
	}

	// 2. Optionally walk git history.
	if in.ScanHistory {
		historyFindings, bytesScanned, herr := scanHistory(ctx, in.TargetPath)
		if herr != nil {
			// Don't fail the whole scan if history isn't available (e.g. no .git
			// dir). Record it and continue — the working-tree scan is still useful.
			if activity.IsActivity(ctx) {
				activity.GetLogger(ctx).Warn("history scan failed", "err", herr)
			}
		} else {
			out.Findings = append(out.Findings, historyFindings...)
			out.HistoryBytesScanned = bytesScanned
		}
	}

	emitter.Emit(sibylproxy.NewNodeCompleted("", nodeID, label,
		map[string]interface{}{
			"files_scanned":  out.FilesScanned,
			"findings_count": len(out.Findings),
		},
		time.Since(started),
	))
	return out, nil
}

// scanBytes applies every rule to the given content and produces findings.
// location is what to report (e.g. file path); origin is "working_tree" or
// "git_history" — used as evidence kind.
func scanBytes(data []byte, location, origin string) []findings.Finding {
	var fs []findings.Finding
	for _, rule := range rules.RegexRules {
		matches := rule.Pattern.FindAllIndex(data, -1)
		for _, m := range matches {
			snippet := string(data[m[0]:m[1]])
			// Entropy filter — skip low-entropy matches when the rule requires it.
			if rule.MinEntropy > 0 && shannonBits(snippet) < rule.MinEntropy {
				continue
			}
			line := lineOf(data, m[0])
			loc := fmt.Sprintf("%s:%d", location, line)
			evidenceKind := "file_line"
			if origin == "git_history" {
				evidenceKind = "git_commit"
			}
			fs = append(fs, findings.Finding{
				ID:        findingID(rule.ID, loc, snippet),
				Category:  findings.CategorySecretExposure,
				Severity:  severityFor(rule.ID, origin),
				Title:     fmt.Sprintf("%s in %s", rule.Description, location),
				Description: fmt.Sprintf(
					"Pattern %q (rule %s) matched at %s. "+
						"This pattern matches known secret formats; if this is a "+
						"real credential, rotate it. If it is a test fixture, "+
						"document it as such so the Critic can reject the finding.",
					rule.Description, rule.ID, loc,
				),
				Evidence: []findings.Evidence{{
					Kind:        evidenceKind,
					Description: fmt.Sprintf("Rule %s matched", rule.ID),
					Location:    loc,
					Snippet:     truncate(snippet, 120),
				}},
				OwnerHint:    location,
				DiscoveredAt: time.Now().UTC(),
				ScannerID:    "regex",
			})
		}
	}
	return fs
}

// scanHistory shells out to `git log -p` and applies rules to the diff output.
// Returns historical findings — secrets that appear in commit diffs (whether
// added or removed). Bytes scanned is approximate.
func scanHistory(ctx context.Context, repoPath string) ([]findings.Finding, int64, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "log", "-p", "--all", "--no-color")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, err
	}
	if err := cmd.Start(); err != nil {
		return nil, 0, err
	}
	defer func() { _ = cmd.Wait() }()

	// Stream and chunk by commit. We don't need every line in memory —
	// we apply rules per chunk and discard.
	var all []findings.Finding
	var bytesScanned int64
	var currentCommit string
	var currentFile string
	var buf bytes.Buffer

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		loc := fmt.Sprintf("%s@%s", currentFile, shortSHA(currentCommit))
		bytesScanned += int64(buf.Len())
		all = append(all, scanBytes(buf.Bytes(), loc, "git_history")...)
		buf.Reset()
	}
	heartbeatEvery := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.HasPrefix(line, []byte("commit ")) {
			flush()
			currentCommit = strings.TrimPrefix(string(line), "commit ")
			currentFile = ""
		} else if bytes.HasPrefix(line, []byte("diff --git ")) {
			flush()
			// Parse: diff --git a/path b/path
			parts := strings.Fields(string(line))
			if len(parts) >= 4 {
				currentFile = strings.TrimPrefix(parts[3], "b/")
			}
		} else if bytes.HasPrefix(line, []byte("+")) || bytes.HasPrefix(line, []byte("-")) {
			// Only scan added/removed lines — the actual content changes.
			buf.Write(line)
			buf.WriteByte('\n')
		}
		heartbeatEvery++
		if heartbeatEvery%500 == 0 {
			heartbeat(ctx, bytesScanned)
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return all, bytesScanned, err
	}
	return all, bytesScanned, nil
}

// Helpers below.

var defaultSkipPatterns = []string{
	"/.git/",
	"/node_modules/",
	"/vendor/",
	"/.venv/",
	"__pycache__",
	".min.js",
	".min.css",
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

func lineOf(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	return bytes.Count(data[:offset], []byte("\n")) + 1
}

func findingID(ruleID, location, snippet string) string {
	h := sha256.Sum256([]byte(ruleID + "|" + location + "|" + snippet))
	return ruleID + "-" + hex.EncodeToString(h[:6])
}

func severityFor(ruleID, origin string) findings.Severity {
	// Historical exposures are typically more severe — the secret was live
	// in production, may have been scraped, and rotation alone doesn't fix it.
	if origin == "git_history" {
		return findings.SeverityCritical
	}
	switch ruleID {
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

func shortSHA(sha string) string {
	if len(sha) >= 7 {
		return sha[:7]
	}
	return sha
}

// shannonBits computes Shannon entropy of s in bits per character.
// Used to filter out low-entropy regex matches that are unlikely to be real
// secrets (e.g. 40 zeros in a row matching the AWS-secret-shaped regex).
func shannonBits(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int, len(s))
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var entropy float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// heartbeat records a Temporal activity heartbeat if the context is an
// activity context. Outside Temporal (e.g. unit tests), it's a no-op.
// This lets the same scanner code run both in workflows and standalone.
func heartbeat(ctx context.Context, details ...interface{}) {
	if !activity.IsActivity(ctx) {
		return
	}
	activity.RecordHeartbeat(ctx, details...)
}
