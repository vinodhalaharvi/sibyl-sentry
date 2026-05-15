// Command sentry-web is a self-contained HTTP+SSE server that runs a
// Sentry worker in-process and exposes the SecurityAuditWorkflow to a
// web UI.
//
// Endpoints:
//
//	GET  /                       — serves the embedded UI
//	POST /run                    — starts a SecurityAuditWorkflow,
//	                                returns {"workflow_id": "..."}
//	GET  /events?workflow_id=X   — SSE stream of all events for that workflow
//	GET  /healthz                — liveness check
//	GET  /metrics                — Prometheus metrics
//
// Why co-located? The broker is in-process pub/sub. For broker events
// emitted by activities to reach the HTTP handler, both must share the
// process. A separate worker + API would require a cross-process bus,
// which we've intentionally not added.
//
// Mirrors sibyl/cmd/api-server's architecture; adapts for Sentry's
// workflow (SecurityAuditWorkflow with VendorEndpoints config).
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/vinodhalaharvi/sibyl-sentry/audit"
	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/internal/sibylproxy"
	"github.com/vinodhalaharvi/sibyl-sentry/jira"
	"github.com/vinodhalaharvi/sibyl-sentry/owners"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/dormancy"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/regex"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/scopes"
)

//go:embed web/index.html
var webFS embed.FS

// Default config carried in the runRequest if the client doesn't override.
// These point at the mock servers from sibyl-sentry-fixtures.
const (
	defaultOktaURL = "http://localhost:9001"
	defaultAWSURL  = "http://localhost:9002"
	defaultGHURL   = "http://localhost:9003"
)

func main() {
	addr := flag.String("addr", ":8090", "HTTP listen address")
	temporalAddr := flag.String("temporal", "localhost:7233", "Temporal address")
	taskQueue := flag.String("queue", "sentry", "Task queue name")
	ownersPath := flag.String("owners", "../sibyl-sentry-fixtures/sentry-config/owners.json", "Path to owners.json")
	defaultTarget := flag.String("default-target", "../sibyl-sentry-fixtures", "Default scan target (fixtures repo)")
	flag.Parse()

	// 1. Broker registered globally so all in-process activities emit
	//    into the same broker the SSE handler subscribes to.
	broker := sibylproxy.NewMemoryBroker()
	defer broker.Close()
	sibylproxy.SetGlobalBroker(broker)
	log.Println("broker registered globally")

	// 2. Temporal client + worker.
	tc, err := client.Dial(client.Options{HostPort: *temporalAddr})
	if err != nil {
		log.Fatalf("temporal dial: %v", err)
	}
	defer tc.Close()

	resolver, err := owners.Load(*ownersPath)
	if err != nil {
		log.Fatalf("owners load: %v", err)
	}

	w := worker.New(tc, *taskQueue, worker.Options{})

	// Sibyl's Researcher/Critic. Scripted in stub mode; the real binary
	// would wire Anthropic / Claude Code.
	complete := sibylproxy.ScriptedComplete("ACCEPTED: evidence is concrete and verifiable.")
	sibylproxy.RegisterEngine(w, complete)

	// Sentry workflow + activities.
	w.RegisterWorkflow(audit.SecurityAuditWorkflow)
	w.RegisterActivityWithOptions(regex.Scan, regexActivityOptions())
	w.RegisterActivityWithOptions(oauth.ScanStale, oauthActivityOptions())
	w.RegisterActivityWithOptions(scopes.ScanOverPrivilege, scopesActivityOptions())
	w.RegisterActivityWithOptions(dormancy.ScanIAM, dormancyActivityOptions())
	jiraActs := jira.NewActivities(jira.NewMockClient(), resolver)
	w.RegisterActivityWithOptions(jiraActs.CreateTicket, jiraActivityOptions())

	if err := w.Start(); err != nil {
		log.Fatalf("worker start: %v", err)
	}
	defer w.Stop()
	log.Printf("worker started on queue %q", *taskQueue)

	// 3. HTTP server.
	srv := &server{
		tc:            tc,
		broker:        broker,
		taskQueue:     *taskQueue,
		defaultTarget: *defaultTarget,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/run", srv.handleRun)
	mux.HandleFunc("/events", srv.handleEvents)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		// Minimal Prometheus-format placeholder. A real /metrics would
		// expose request counters, broker queue depth, scanner timings,
		// etc. — wired via prometheus/client_golang once we adopt it.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintln(w, "# HELP sentry_web_up sentry-web process up")
		_, _ = fmt.Fprintln(w, "# TYPE sentry_web_up gauge")
		_, _ = fmt.Fprintln(w, "sentry_web_up 1")
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// 4. Graceful shutdown.
	idleClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		close(idleClosed)
	}()

	log.Printf("listening on http://localhost%s", *addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http serve: %v", err)
	}
	<-idleClosed
}

// server holds the deps that handlers need.
type server struct {
	tc            client.Client
	broker        *sibylproxy.MemoryBroker
	taskQueue     string
	defaultTarget string
}

// --- Handlers ---

// handleIndex serves the embedded UI from web/index.html.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		http.Error(w, "ui missing: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "ui missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// runRequest is the POST /run payload. All vendor URLs default to the
// mock URLs if not specified.
type runRequest struct {
	TargetPath        string `json:"target_path,omitempty"`
	OktaURL           string `json:"okta_url,omitempty"`
	OktaToken         string `json:"okta_token,omitempty"`
	AWSURL            string `json:"aws_url,omitempty"`
	AWSToken          string `json:"aws_token,omitempty"`
	GitHubURL         string `json:"github_url,omitempty"`
	GitHubToken       string `json:"github_token,omitempty"`
	FileTickets       bool   `json:"file_tickets"`
	MinTicketSeverity string `json:"min_severity,omitempty"`
}

// runResponse is what POST /run returns.
type runResponse struct {
	WorkflowID string `json:"workflow_id"`
}

// handleRun starts a SecurityAuditWorkflow. Returns immediately with the
// workflow ID; the client subscribes to /events to watch.
func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req runRequest
	// Body is optional; an empty POST gets default everything.
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.TargetPath == "" {
		req.TargetPath = s.defaultTarget
	}
	if req.OktaURL == "" {
		req.OktaURL = defaultOktaURL
	}
	if req.OktaToken == "" {
		req.OktaToken = "demo-okta-token"
	}
	if req.AWSURL == "" {
		req.AWSURL = defaultAWSURL
	}
	if req.AWSToken == "" {
		req.AWSToken = "demo-aws-token"
	}
	if req.GitHubURL == "" {
		req.GitHubURL = defaultGHURL
	}
	if req.GitHubToken == "" {
		req.GitHubToken = "demo-github-token"
	}

	wfID := "sentry-audit-" + uuid.NewString()[:8]

	in := audit.AuditInput{
		TargetPath: req.TargetPath,
		VendorEndpoints: audit.VendorEndpoints{
			OktaBaseURL:   req.OktaURL,
			OktaToken:     req.OktaToken,
			AWSBaseURL:    req.AWSURL,
			AWSToken:      req.AWSToken,
			GitHubBaseURL: req.GitHubURL,
			GitHubToken:   req.GitHubToken,
		},
		FileTickets:       req.FileTickets,
		MinTicketSeverity: parseSeverity(req.MinTicketSeverity),
	}

	_, err := s.tc.ExecuteWorkflow(r.Context(),
		client.StartWorkflowOptions{
			ID:        wfID,
			TaskQueue: s.taskQueue,
		},
		audit.WorkflowName, in,
	)
	if err != nil {
		http.Error(w, "start workflow: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Synthetic workflow.started — the UI wants to know "the audit exists
	// now" without waiting for the first scanner's NodeStarted event.
	s.broker.Publish(sibylproxy.NewWorkflowStarted(wfID, audit.WorkflowName, in))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(runResponse{WorkflowID: wfID})
	log.Printf("run started: %s target=%s", wfID, req.TargetPath)
}

// handleEvents implements SSE for /events?workflow_id=X. Subscribes to
// the broker, forwards events as SSE messages, closes on terminal event
// (workflow.completed / workflow.failed) or client disconnect.
func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	workflowID := r.URL.Query().Get("workflow_id")
	if workflowID == "" {
		http.Error(w, "workflow_id required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Generous buffer — slow consumer drops events, doesn't slow scanners.
	ch, cancel := s.broker.Subscribe(workflowID, 256)
	defer cancel()

	_, _ = fmt.Fprintf(w, ": connected to %s\n\n", workflowID)
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// In parallel, watch the workflow's actual termination via Temporal's
	// run.Get — emits a synthetic workflow.completed/failed when it ends.
	// Without this, the scanner-emitted events would stream fine but the
	// SSE wouldn't know when the workflow ended (scanners don't emit
	// workflow-level events; the api-server does).
	go s.watchWorkflowResult(workflowID)

	var done atomic.Bool
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind(), payload)
			flusher.Flush()
			switch ev.(type) {
			case sibylproxy.WorkflowCompleted, sibylproxy.WorkflowFailed:
				done.Store(true)
			}
			if done.Load() {
				time.Sleep(50 * time.Millisecond)
				return
			}
		}
	}
}

// watchWorkflowResult subscribes to the workflow's completion via
// Temporal and emits a synthetic workflow.completed (or workflow.failed)
// when it terminates. Runs in its own goroutine, scoped to each SSE
// connection so a long-running workflow with reconnecting clients still
// gets a final event per connection.
func (s *server) watchWorkflowResult(workflowID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	run := s.tc.GetWorkflow(ctx, workflowID, "")
	started := time.Now()

	var out audit.AuditOutput
	err := run.Get(ctx, &out)
	dur := time.Since(started)
	if err != nil {
		s.broker.Publish(sibylproxy.NewWorkflowFailed(workflowID, err, dur))
		return
	}
	// Compact summary for the UI so it can render immediately on
	// workflow.completed without a separate fetch.
	summary := map[string]interface{}{
		"findings_count":     len(out.Report.Findings),
		"tickets_filed":      len(out.Tickets),
		"errors_count":       len(out.Report.Errors),
		"completed_at":       out.Report.CompletedAt,
		"started_at":         out.Report.StartedAt,
		"duration_seconds":   out.Report.CompletedAt.Sub(out.Report.StartedAt).Seconds(),
	}
	s.broker.Publish(sibylproxy.NewWorkflowCompleted(workflowID, summary, dur))
}

// parseSeverity maps the request's string severity to the findings type.
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
	}
	return findings.SeverityHigh
}
