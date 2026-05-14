// Package jira files Jira tickets for security findings.
//
// For the hackathon demo, the default client is a MockClient that prints
// tickets to stdout (and returns synthetic ticket keys). To wire to real
// Jira, implement the Client interface against your Jira instance — the
// activity itself is unchanged.
package jira

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/findings"
	"github.com/vinodhalaharvi/sibyl-sentry/owners"
)

const ActivityName = "jira.CreateTicket"

// Client is the abstraction the activity uses to file tickets.
// Implementations: MockClient (default), and a future RealClient.
type Client interface {
	CreateIssue(ctx context.Context, in CreateIssueInput) (CreateIssueOutput, error)
}

type CreateIssueInput struct {
	Project     string
	Assignee    string
	Summary     string
	Description string
	Labels      []string
	Severity    string
}

type CreateIssueOutput struct {
	Key string // e.g. "BILL-1234"
	URL string
}

// CreateTicketInput is the activity input. The activity itself is
// constructed with a Client + Resolver via NewActivities below.
type CreateTicketInput struct {
	Finding   findings.Finding
	DryRun    bool // if true, don't actually call the client
	MinSeverity findings.Severity // skip findings below this; 0 = no filter
}

type CreateTicketOutput struct {
	Filed      bool
	TicketKey  string
	TicketURL  string
	Assignment owners.Assignment
	SkipReason string
}

// Activities groups the dependency-injected dependencies for Jira activities.
// Register an instance with the Temporal worker.
type Activities struct {
	Client   Client
	Resolver *owners.Resolver
}

func NewActivities(client Client, resolver *owners.Resolver) *Activities {
	return &Activities{Client: client, Resolver: resolver}
}

// CreateTicket files a Jira ticket for a finding. If MinSeverity is set,
// findings below it are skipped (with reason recorded in output).
func (a *Activities) CreateTicket(ctx context.Context, in CreateTicketInput) (*CreateTicketOutput, error) {
	if in.MinSeverity > 0 && in.Finding.Severity < in.MinSeverity {
		return &CreateTicketOutput{
			Filed:      false,
			SkipReason: fmt.Sprintf("severity %s below threshold %s", in.Finding.Severity, in.MinSeverity),
		}, nil
	}
	assignment := a.Resolver.Resolve(in.Finding)

	if in.DryRun {
		return &CreateTicketOutput{
			Filed:      false,
			Assignment: assignment,
			SkipReason: "dry run",
		}, nil
	}

	out, err := a.Client.CreateIssue(ctx, CreateIssueInput{
		Project:     assignment.JiraProject,
		Assignee:    assignment.Assignee,
		Summary:     fmt.Sprintf("[Sentry] %s", in.Finding.Title),
		Description: formatDescription(in.Finding, assignment),
		Labels:      []string{"sentry", "security", string(in.Finding.Category)},
		Severity:    in.Finding.Severity.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("jira.CreateTicket: %w", err)
	}
	return &CreateTicketOutput{
		Filed:      true,
		TicketKey:  out.Key,
		TicketURL:  out.URL,
		Assignment: assignment,
	}, nil
}

// formatDescription builds the ticket body from a finding, including
// evidence so the assignee can verify without re-running the scanner.
func formatDescription(f findings.Finding, a owners.Assignment) string {
	desc := fmt.Sprintf(
		"Severity: %s\nCategory: %s\nDiscovered: %s\nDetected by: %s\n\n%s\n",
		f.Severity, f.Category, f.DiscoveredAt.Format(time.RFC3339), f.ScannerID,
		f.Description,
	)
	if len(f.Evidence) > 0 {
		desc += "\nEvidence:\n"
		for _, e := range f.Evidence {
			desc += fmt.Sprintf("- [%s] %s", e.Kind, e.Description)
			if e.Location != "" {
				desc += fmt.Sprintf(" @ %s", e.Location)
			}
			if e.Snippet != "" {
				desc += fmt.Sprintf("\n    %s", e.Snippet)
			}
			desc += "\n"
		}
	}
	if a.TeamChannel != "" {
		desc += fmt.Sprintf("\nCc: %s", a.TeamChannel)
	}
	return desc
}

// MockClient is a demo-time Client that prints to stdout and returns
// synthetic ticket keys. Useful for the hackathon demo without needing
// real Jira credentials.
type MockClient struct {
	counter atomic.Int64
}

func NewMockClient() *MockClient {
	return &MockClient{}
}

func (m *MockClient) CreateIssue(_ context.Context, in CreateIssueInput) (CreateIssueOutput, error) {
	n := m.counter.Add(1)
	key := fmt.Sprintf("%s-%d", in.Project, 1000+n)
	url := fmt.Sprintf("https://jira.example.com/browse/%s", key)
	fmt.Fprintf(os.Stderr, "\n========== MOCK JIRA TICKET ==========\n")
	fmt.Fprintf(os.Stderr, "Key:      %s\n", key)
	fmt.Fprintf(os.Stderr, "Project:  %s\n", in.Project)
	fmt.Fprintf(os.Stderr, "Assignee: %s\n", in.Assignee)
	fmt.Fprintf(os.Stderr, "Severity: %s\n", in.Severity)
	fmt.Fprintf(os.Stderr, "Labels:   %v\n", in.Labels)
	fmt.Fprintf(os.Stderr, "Summary:  %s\n", in.Summary)
	fmt.Fprintf(os.Stderr, "\n%s\n", in.Description)
	fmt.Fprintf(os.Stderr, "======================================\n\n")
	return CreateIssueOutput{Key: key, URL: url}, nil
}
