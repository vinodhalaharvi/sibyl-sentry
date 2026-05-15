//go:build !sibyl_stub

// Package sibylproxy: real-Sibyl adapter. When building without the
// sibyl_stub tag, this file aliases the proxy types to real Sibyl.
package sibylproxy

import (
	"context"
	"fmt"

	"go.temporal.io/sdk/worker"

	"github.com/vinodhalaharvi/sibyl/agent"
	sibylworker "github.com/vinodhalaharvi/sibyl/worker"
)

// CompleteFunc aliases Sibyl's LLM seam type.
type CompleteFunc = agent.CompleteFunc

// Question and Answer alias Sibyl's input/output types.
type Question = agent.Question
type Answer = agent.Answer
type Round = agent.Round
type Verdict = agent.Verdict

// ConvergeWorkflowName matches Sibyl's registered name so the audit
// workflow can ExecuteChildWorkflow against this string identically in
// both stub and real builds.
const ConvergeWorkflowName = "ConvergeWorkflow"

// RegisterEngine wires Sibyl's workflows onto a Temporal worker.
func RegisterEngine(w worker.Worker, complete CompleteFunc) {
	sibylworker.Register(w, complete)
}

// ScriptedComplete returns a CompleteFunc that returns the given response
// for any prompt.
func ScriptedComplete(response string) CompleteFunc {
	return func(_ context.Context, _, _ string) (string, error) {
		return response, nil
	}
}

// PickBackend resolves a backend name to a CompleteFunc, matching Sibyl's
// cmd/api-server semantics:
//
//   "scripted"     → static response (for CI / smoke tests)
//   "anthropic"    → Sibyl's Anthropic client (needs ANTHROPIC_API_KEY)
//   "claude-code"  → Sibyl's Claude Code client (uses local CC session)
//
// model is the LLM model name (passed through to the backend); empty
// means "the backend's default".
func PickBackend(name, model string) (CompleteFunc, error) {
	switch name {
	case "scripted":
		s := &agent.ScriptedLLM{Cycle: true, Responses: []string{
			"DECISION: ACCEPTED\nSEVERITY: HIGH\nRATIONALE: Scripted backend — evidence accepted as-is for smoke testing.\nREVISED_DESCRIPTION: (scripted) original description retained.",
		}}
		return s.Complete, nil
	case "anthropic":
		cfg := agent.AnthropicConfig{Model: model}
		c, err := agent.NewAnthropicClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("anthropic client: %w", err)
		}
		return c.Complete, nil
	case "claude-code":
		cfg := agent.ClaudeCodeConfig{Model: model}
		return agent.NewClaudeCodeClient(cfg).Complete, nil
	default:
		return nil, fmt.Errorf("unknown llm backend %q (try: scripted | anthropic | claude-code)", name)
	}
}

// ---------------------------------------------------------------------------
// Event types — aliased to Sibyl's agent.Event hierarchy.
// ---------------------------------------------------------------------------

// Event is Sibyl's event interface.
type Event = agent.Event

// Concrete event types.
type WorkflowStarted = agent.WorkflowStarted
type WorkflowCompleted = agent.WorkflowCompleted
type WorkflowFailed = agent.WorkflowFailed
type NodeStarted = agent.NodeStarted
type NodeCompleted = agent.NodeCompleted
type NodeFailed = agent.NodeFailed

// Constructors aliased.
var (
	NewWorkflowStarted   = agent.NewWorkflowStarted
	NewWorkflowCompleted = agent.NewWorkflowCompleted
	NewWorkflowFailed    = agent.NewWorkflowFailed
	NewNodeStarted       = agent.NewNodeStarted
	NewNodeCompleted     = agent.NewNodeCompleted
	NewNodeFailed        = agent.NewNodeFailed
)

// ---------------------------------------------------------------------------
// Broker + Emitter aliased.
// ---------------------------------------------------------------------------

// Broker aliases Sibyl's broker interface.
type Broker = agent.Broker

// MemoryBroker is the in-process default broker.
type MemoryBroker = agent.MemoryBroker

// NewMemoryBroker constructs one.
var NewMemoryBroker = agent.NewMemoryBroker

// SetGlobalBroker registers the process-wide broker.
var SetGlobalBroker = agent.SetGlobalBroker

// Emitter is the workflow-scoped publisher.
type Emitter = agent.Emitter

// EmitterForActivity returns the Emitter tied to the current activity's
// workflow ID via Sibyl's helper.
var EmitterForActivity = agent.EmitterForActivity
