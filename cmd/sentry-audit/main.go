// Command sentry-audit submits a SecurityAuditWorkflow against a target
// directory and prints the synthesized report when complete.
//
// Usage:
//
//	sentry-audit -target ../sibyl-sentry-fixtures
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"go.temporal.io/sdk/client"

	"github.com/vinodhalaharvi/sibyl-sentry/audit"
	"github.com/vinodhalaharvi/sibyl-sentry/findings"
)

func main() {
	var (
		temporalAddr = flag.String("temporal", "localhost:7233", "Temporal server address")
		taskQueue    = flag.String("queue", "sentry", "Task queue name")
		target       = flag.String("target", "", "Target path to scan (required)")
		fileTickets  = flag.Bool("file-tickets", true, "File Jira tickets for findings")
		jsonOut      = flag.Bool("json", false, "Print JSON output (default: human-readable)")
		minSev       = flag.String("min-severity", "high", "Minimum severity to file tickets: info|low|medium|high|critical")
	)
	flag.Parse()

	if *target == "" {
		log.Fatal("missing -target")
	}
	abs, err := filepath.Abs(*target)
	if err != nil {
		log.Fatalf("resolve target: %v", err)
	}

	c, err := client.Dial(client.Options{HostPort: *temporalAddr})
	if err != nil {
		log.Fatalf("temporal dial: %v", err)
	}
	defer c.Close()

	in := audit.AuditInput{
		TargetPath: abs,
		Inventories: audit.Inventories{
			OAuthClients: filepath.Join(abs, "config/oauth-clients.json"),
		},
		EnabledScanners:   []audit.ScannerID{audit.ScannerSecrets, audit.ScannerOAuth},
		FileTickets:       *fileTickets,
		MinTicketSeverity: parseSeverity(*minSev),
	}

	run, err := c.ExecuteWorkflow(context.Background(),
		client.StartWorkflowOptions{
			TaskQueue: *taskQueue,
		},
		audit.WorkflowName, in,
	)
	if err != nil {
		log.Fatalf("execute workflow: %v", err)
	}
	log.Printf("workflow started: id=%s run=%s", run.GetID(), run.GetRunID())

	var out audit.AuditOutput
	if err := run.Get(context.Background(), &out); err != nil {
		log.Fatalf("workflow result: %v", err)
	}

	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	printHuman(out)
}

func parseSeverity(s string) findings.Severity {
	switch s {
	case "info":
		return findings.SeverityInfo
	case "low":
		return findings.SeverityLow
	case "medium":
		return findings.SeverityMedium
	case "high":
		return findings.SeverityHigh
	case "critical":
		return findings.SeverityCritical
	default:
		return findings.SeverityHigh
	}
}

func printHuman(out audit.AuditOutput) {
	r := out.Report
	fmt.Printf("\n=== Sentry Audit Report ===\n")
	fmt.Printf("Target:    %s\n", r.Target)
	fmt.Printf("Started:   %s\n", r.StartedAt.Format("15:04:05"))
	fmt.Printf("Completed: %s (%.1fs)\n", r.CompletedAt.Format("15:04:05"), r.CompletedAt.Sub(r.StartedAt).Seconds())
	fmt.Printf("Findings:  %d\n", len(r.Findings))
	if len(r.Errors) > 0 {
		fmt.Printf("Errors:    %d\n", len(r.Errors))
		for _, e := range r.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}
	fmt.Println()

	for i, f := range r.Findings {
		fmt.Printf("[%d] %s  %s\n", i+1, f.Severity, f.Title)
		fmt.Printf("    %s\n", f.Description)
		for _, e := range f.Evidence {
			fmt.Printf("    evidence: [%s] %s", e.Kind, e.Description)
			if e.Location != "" {
				fmt.Printf(" @ %s", e.Location)
			}
			fmt.Println()
			if e.Snippet != "" {
				fmt.Printf("              %s\n", e.Snippet)
			}
		}
		fmt.Println()
	}

	if len(out.Tickets) > 0 {
		fmt.Printf("=== Tickets Filed ===\n")
		for _, t := range out.Tickets {
			if t.Filed {
				fmt.Printf("  %s  (finding %s)  %s\n", t.Key, t.FindingID, t.URL)
			} else {
				fmt.Printf("  -      (finding %s)  skip: %s\n", t.FindingID, t.Skip)
			}
		}
		fmt.Println()
	}
}
