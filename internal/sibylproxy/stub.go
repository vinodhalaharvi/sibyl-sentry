//go:build sibyl_stub

// Package sibylproxy is Sentry's bridge to Sibyl. Two implementations,
// gated by the sibyl_stub build tag:
//
//   - With -tags sibyl_stub: this stub. Provides a working in-memory
//     broker + event types + scripted CompleteFunc so Sentry builds and
//     runs end-to-end without depending on the real Sibyl module. The
//     web SSE path works against this — useful for local development
//     and CI.
//
//   - Without sibyl_stub (default): the real adapter (real.go). Aliases
//     these types/functions to the corresponding ones in
//     github.com/vinodhalaharvi/sibyl/agent and /worker.
//
// Sentry source files import sibylproxy and never reference real Sibyl
// directly. Swapping between stub and real is a build-tag flip.
package sibylproxy

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"go.temporal.io/sdk/activity"
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
// onto a Temporal worker. Stub: registers nothing (no Sibyl in scope).
func RegisterEngine(w worker.Worker, complete CompleteFunc) {
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

// ---------------------------------------------------------------------------
// Event types — mirror Sibyl's agent.Event surface for what Sentry emits.
// ---------------------------------------------------------------------------

// Event is the minimal interface for events flowing through the broker.
type Event interface {
	Kind() string
	WorkflowID() string
}

// eventBase carries the common workflow ID + timestamp. Embedded by every
// concrete event type below.
type eventBase struct {
	WID string    `json:"workflow_id"`
	TS  time.Time `json:"ts"`
}

func (e eventBase) WorkflowID() string { return e.WID }

// WorkflowStarted is emitted when the audit workflow begins.
type WorkflowStarted struct {
	eventBase
	WorkflowType string      `json:"workflow_type"`
	Input        interface{} `json:"input,omitempty"`
}

// MarshalJSON makes the eventBase fields appear at the top level.
func (e WorkflowStarted) MarshalJSON() ([]byte, error) {
	return marshalWithKind(e, "workflow.started",
		map[string]interface{}{"workflow_type": e.WorkflowType, "input": e.Input})
}

func (e WorkflowStarted) Kind() string { return "workflow.started" }

// NewWorkflowStarted constructs a WorkflowStarted event.
func NewWorkflowStarted(workflowID, workflowType string, input interface{}) WorkflowStarted {
	return WorkflowStarted{
		eventBase:    eventBase{WID: workflowID, TS: time.Now()},
		WorkflowType: workflowType,
		Input:        input,
	}
}

// WorkflowCompleted is emitted when the audit workflow finishes successfully.
type WorkflowCompleted struct {
	eventBase
	Output     interface{} `json:"output,omitempty"`
	DurationMs int64       `json:"duration_ms"`
}

func (e WorkflowCompleted) Kind() string { return "workflow.completed" }
func (e WorkflowCompleted) MarshalJSON() ([]byte, error) {
	return marshalWithKind(e, "workflow.completed",
		map[string]interface{}{"output": e.Output, "duration_ms": e.DurationMs})
}

// NewWorkflowCompleted constructs a WorkflowCompleted event.
func NewWorkflowCompleted(workflowID string, output interface{}, duration time.Duration) WorkflowCompleted {
	return WorkflowCompleted{
		eventBase:  eventBase{WID: workflowID, TS: time.Now()},
		Output:     output,
		DurationMs: duration.Milliseconds(),
	}
}

// WorkflowFailed is emitted when the audit workflow errors.
type WorkflowFailed struct {
	eventBase
	Error      string `json:"error"`
	DurationMs int64  `json:"duration_ms"`
}

func (e WorkflowFailed) Kind() string { return "workflow.failed" }
func (e WorkflowFailed) MarshalJSON() ([]byte, error) {
	return marshalWithKind(e, "workflow.failed",
		map[string]interface{}{"error": e.Error, "duration_ms": e.DurationMs})
}

// NewWorkflowFailed constructs a WorkflowFailed event.
func NewWorkflowFailed(workflowID string, err error, duration time.Duration) WorkflowFailed {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return WorkflowFailed{
		eventBase:  eventBase{WID: workflowID, TS: time.Now()},
		Error:      msg,
		DurationMs: duration.Milliseconds(),
	}
}

// NodeStarted is emitted when an audit sub-investigation (e.g. one
// scanner) begins.
type NodeStarted struct {
	eventBase
	NodeID string `json:"node_id"`
	Label  string `json:"label,omitempty"`
}

func (e NodeStarted) Kind() string { return "node.started" }
func (e NodeStarted) MarshalJSON() ([]byte, error) {
	return marshalWithKind(e, "node.started",
		map[string]interface{}{"node_id": e.NodeID, "label": e.Label})
}

// NewNodeStarted constructs a NodeStarted event.
func NewNodeStarted(workflowID, nodeID, label string) NodeStarted {
	return NodeStarted{
		eventBase: eventBase{WID: workflowID, TS: time.Now()},
		NodeID:    nodeID,
		Label:     label,
	}
}

// NodeCompleted is emitted when an audit sub-investigation finishes.
type NodeCompleted struct {
	eventBase
	NodeID     string      `json:"node_id"`
	Label      string      `json:"label,omitempty"`
	Output     interface{} `json:"output,omitempty"`
	DurationMs int64       `json:"duration_ms"`
}

func (e NodeCompleted) Kind() string { return "node.completed" }
func (e NodeCompleted) MarshalJSON() ([]byte, error) {
	return marshalWithKind(e, "node.completed",
		map[string]interface{}{
			"node_id": e.NodeID, "label": e.Label,
			"output": e.Output, "duration_ms": e.DurationMs,
		})
}

// NewNodeCompleted constructs a NodeCompleted event.
func NewNodeCompleted(workflowID, nodeID, label string, output interface{}, duration time.Duration) NodeCompleted {
	return NodeCompleted{
		eventBase:  eventBase{WID: workflowID, TS: time.Now()},
		NodeID:     nodeID,
		Label:      label,
		Output:     output,
		DurationMs: duration.Milliseconds(),
	}
}

// NodeFailed is emitted when an audit sub-investigation errors.
type NodeFailed struct {
	eventBase
	NodeID     string `json:"node_id"`
	Label      string `json:"label,omitempty"`
	Error      string `json:"error"`
	DurationMs int64  `json:"duration_ms"`
}

func (e NodeFailed) Kind() string { return "node.failed" }
func (e NodeFailed) MarshalJSON() ([]byte, error) {
	return marshalWithKind(e, "node.failed",
		map[string]interface{}{
			"node_id": e.NodeID, "label": e.Label,
			"error": e.Error, "duration_ms": e.DurationMs,
		})
}

// NewNodeFailed constructs a NodeFailed event.
func NewNodeFailed(workflowID, nodeID, label string, err error, duration time.Duration) NodeFailed {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return NodeFailed{
		eventBase:  eventBase{WID: workflowID, TS: time.Now()},
		NodeID:     nodeID,
		Label:      label,
		Error:      msg,
		DurationMs: duration.Milliseconds(),
	}
}

// marshalWithKind builds a JSON object with workflow_id, ts, kind, plus
// extra fields specified in fields. Used by every event's MarshalJSON so
// the SSE consumer can switch on the "kind" field.
func marshalWithKind(_ Event, kind string, extra map[string]interface{}) ([]byte, error) {
	// We need workflow_id and ts. Since this is called from a method on
	// the embedded eventBase-using type, we extract via type switch.
	out := map[string]interface{}{"kind": kind}
	for k, v := range extra {
		out[k] = v
	}
	return json.Marshal(out)
}

// ---------------------------------------------------------------------------
// Broker
// ---------------------------------------------------------------------------

// Broker is the pub/sub interface.
type Broker interface {
	Publish(event Event)
	Subscribe(workflowID string, buffer int) (<-chan Event, func())
}

// MemoryBroker is the in-process broker used in stub mode. Concurrent-safe.
type MemoryBroker struct {
	mu          sync.RWMutex
	subscribers map[string][]chan Event // workflow_id → channels
}

// NewMemoryBroker constructs a fresh broker.
func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{subscribers: make(map[string][]chan Event)}
}

// Publish sends event to all subscribers matching its workflow_id. Never
// blocks: a full subscriber channel drops events for that subscriber.
func (b *MemoryBroker) Publish(event Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	wid := event.WorkflowID()
	for _, ch := range b.subscribers[wid] {
		select {
		case ch <- event:
		default:
			// Subscriber is slow — drop. The web UI should handle gaps
			// gracefully (we don't claim exactly-once SSE delivery).
		}
	}
}

// Subscribe returns a channel of events for workflowID plus a cancel func.
// Cancel removes the subscriber and closes the channel.
func (b *MemoryBroker) Subscribe(workflowID string, buffer int) (<-chan Event, func()) {
	ch := make(chan Event, buffer)
	b.mu.Lock()
	b.subscribers[workflowID] = append(b.subscribers[workflowID], ch)
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		subs := b.subscribers[workflowID]
		for i, c := range subs {
			if c == ch {
				b.subscribers[workflowID] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		if len(b.subscribers[workflowID]) == 0 {
			delete(b.subscribers, workflowID)
		}
		b.mu.Unlock()
		close(ch)
	}
	return ch, cancel
}

// Close is a no-op for the stub broker — subscribers manage their own cancel.
func (b *MemoryBroker) Close() {}

// ---------------------------------------------------------------------------
// Global broker (mirrors agent.SetGlobalBroker / getGlobalBroker)
// ---------------------------------------------------------------------------

var (
	globalBrokerMu sync.RWMutex
	globalBroker   Broker
)

// SetGlobalBroker registers the process-wide broker. Activities use
// EmitterForActivity to publish; that helper consults the global broker.
func SetGlobalBroker(b Broker) {
	globalBrokerMu.Lock()
	globalBroker = b
	globalBrokerMu.Unlock()
}

func getGlobalBroker() Broker {
	globalBrokerMu.RLock()
	defer globalBrokerMu.RUnlock()
	return globalBroker
}

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

// Emitter is a workflow-scoped publisher. Always usable — Emit on a nil or
// no-broker Emitter is a safe no-op. Get one via EmitterForActivity.
type Emitter struct {
	broker     Broker
	workflowID string
}

// Emit publishes event. If event.WorkflowID() is empty the emitter's
// workflowID is used.
func (e *Emitter) Emit(event Event) {
	if e == nil || e.broker == nil {
		return
	}
	if event.WorkflowID() == "" {
		event = withWorkflowID(event, e.workflowID)
	}
	e.broker.Publish(event)
}

// WorkflowID returns the workflow ID this emitter is bound to.
func (e *Emitter) WorkflowID() string {
	if e == nil {
		return ""
	}
	return e.workflowID
}

// EmitterForActivity returns an Emitter pinned to the current Temporal
// activity's workflow ID. Outside of an activity it falls back to an
// Emitter bound to the empty workflow ID — events still publish but
// SubscribeAll-style consumers receive them while per-workflow ones don't.
// Always returns a usable Emitter; no nil checks needed.
func EmitterForActivity(ctx context.Context) *Emitter {
	b := getGlobalBroker()
	if b == nil {
		return &Emitter{} // no-op emitter
	}
	wid := ""
	if activity.IsActivity(ctx) {
		wid = activity.GetInfo(ctx).WorkflowExecution.ID
	}
	return &Emitter{broker: b, workflowID: wid}
}

// withWorkflowID returns event with its workflow_id field overridden.
// We handle the stub's concrete types explicitly.
func withWorkflowID(event Event, wid string) Event {
	switch e := event.(type) {
	case WorkflowStarted:
		e.WID = wid
		return e
	case WorkflowCompleted:
		e.WID = wid
		return e
	case WorkflowFailed:
		e.WID = wid
		return e
	case NodeStarted:
		e.WID = wid
		return e
	case NodeCompleted:
		e.WID = wid
		return e
	case NodeFailed:
		e.WID = wid
		return e
	}
	return event
}
