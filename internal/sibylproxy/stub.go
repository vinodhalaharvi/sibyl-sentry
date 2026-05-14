//go:build sibyl_stub

// Package sibylproxy provides a minimal stub of Sibyl's public API,
// used only when building with -tags sibyl_stub. The real Sentry binary
// imports github.com/vinodhalaharvi/sibyl/agent and /worker directly;
// this stub exists so the scaffold compiles and tests run in environments
// where the real Sibyl module hasn't been fetched yet.
//
// Replace all references to sibylproxy in Sentry's code with the real
// Sibyl packages once available:
//
//	internal/sibylproxy.CompleteFunc       → agent.CompleteFunc
//	internal/sibylproxy.RegisterEngine     → worker.Register
//	internal/sibylproxy.ConvergeWorkflow   → agent.ConvergeWorkflow
//	internal/sibylproxy.SupervisorWorkflow → agent.SupervisorWorkflow
package sibylproxy

import (
	"context"

	"go.temporal.io/sdk/worker"
)

// CompleteFunc is Sibyl's LLM seam: given a system prompt and a user
// message, return a string completion.
type CompleteFunc func(ctx context.Context, system, user string) (string, error)

// Question is Sibyl's ConvergeWorkflow input.
type Question struct {
	Text      string
	MaxRounds int
}

// Answer is Sibyl's ConvergeWorkflow output.
type Answer struct {
	Text     string
	Accepted bool
	Rounds   int
}

// RegisterEngine wires Sibyl's Researcher/Critic workflows and activities
// onto a Temporal worker. In the real Sibyl this is worker.Register(w, complete).
func RegisterEngine(w worker.Worker, complete CompleteFunc) {
	// Stub: registers nothing. The scaffold compiles; running this stub
	// worker will not actually execute any Sibyl workflows.
	_ = w
	_ = complete
}

// ScriptedComplete returns a CompleteFunc that returns the given response
// for any prompt. Used by tests in stub mode.
func ScriptedComplete(response string) CompleteFunc {
	return func(_ context.Context, _, _ string) (string, error) {
		return response, nil
	}
}
