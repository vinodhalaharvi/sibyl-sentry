//go:build !sibyl_stub

// Package sibylproxy: real-Sibyl adapter. When building without the
// sibyl_stub tag, this file aliases the proxy types to the real Sibyl
// package types, so Sentry code that references sibylproxy.* compiles
// against real Sibyl without any code changes.
package sibylproxy

import (
	"context"

	"go.temporal.io/sdk/worker"

	"github.com/vinodhalaharvi/sibyl/agent"
	sibylworker "github.com/vinodhalaharvi/sibyl/worker"
)

// CompleteFunc aliases Sibyl's LLM seam type.
type CompleteFunc = agent.CompleteFunc

// Question and Answer alias Sibyl's input/output types for the ConvergeWorkflow.
// If real Sibyl's types differ (e.g. it uses agent.Question with different
// fields), adjust these aliases; the rest of Sentry uses sibylproxy.Question.
type Question = agent.Question
type Answer = agent.Answer

// RegisterEngine wires Sibyl's workflows onto a Temporal worker.
func RegisterEngine(w worker.Worker, complete CompleteFunc) {
	sibylworker.Register(w, complete)
}

// ScriptedComplete returns a CompleteFunc that returns the given response
// for any prompt. Real Sibyl exposes ScriptedLLM; this is a thin convenience
// for parity with the stub.
func ScriptedComplete(response string) CompleteFunc {
	return func(_ context.Context, _, _ string) (string, error) {
		return response, nil
	}
}
