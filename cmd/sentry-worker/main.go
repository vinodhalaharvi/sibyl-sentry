// Command sentry-worker runs a Temporal worker that hosts:
//   - Sibyl's workflows and activities (ConvergeWorkflow, Researcher,
//     Critic) registered via sibylproxy.RegisterEngine.
//   - Sentry's SecurityAuditWorkflow.
//   - Sentry's scanner activities (regex secret scan; oauth stale-grant).
//   - Sentry's Jira ticket activity.
//
// Build with -tags yara to use the YARA scanner instead of regex.
// Build with -tags sibyl_stub to skip the real Sibyl dependency.
package main

import (
	"flag"
	"log"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/vinodhalaharvi/sibyl-sentry/audit"
	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
	"github.com/vinodhalaharvi/sibyl-sentry/jira"
	"github.com/vinodhalaharvi/sibyl-sentry/owners"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/regex"
)

func main() {
	var (
		temporalAddr = flag.String("temporal", "localhost:7233", "Temporal server address")
		taskQueue    = flag.String("queue", "sentry", "Task queue name")
		ownersPath   = flag.String("owners", "../sibyl-sentry-fixtures/config/owners.json", "Path to owners.json")
	)
	flag.Parse()

	// 1. Temporal client.
	c, err := client.Dial(client.Options{HostPort: *temporalAddr})
	if err != nil {
		log.Fatalf("temporal dial: %v", err)
	}
	defer c.Close()

	// 2. Owners resolver for the Jira activity.
	resolver, err := owners.Load(*ownersPath)
	if err != nil {
		log.Fatalf("owners load: %v", err)
	}

	// 3. Worker.
	w := worker.New(c, *taskQueue, worker.Options{})

	// 4. Register Sibyl's workflows/activities (ConvergeWorkflow, Researcher,
	// Critic) via the proxy. The CompleteFunc is scripted for the scaffold —
	// swap for sibylproxy adapters around Anthropic / Claude Code in real use.
	complete := sibylproxy.ScriptedComplete("ACCEPTED: evidence is concrete and verifiable.")
	sibylproxy.RegisterEngine(w, complete)

	// 5. Register Sentry workflows and activities.
	w.RegisterWorkflow(audit.SecurityAuditWorkflow)

	w.RegisterActivityWithOptions(regex.Scan, regexActivityOptions())
	w.RegisterActivityWithOptions(oauth.ScanStale, oauthActivityOptions())

	jiraActs := jira.NewActivities(jira.NewMockClient(), resolver)
	w.RegisterActivityWithOptions(jiraActs.CreateTicket, jiraActivityOptions())

	log.Printf("sentry-worker starting on queue %q (temporal=%s)", *taskQueue, *temporalAddr)
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatalf("worker.Run: %v", err)
	}
}
