// Package channels provides a polymorphic, function-seam-based abstraction for
// agentic workflows to send messages to and receive responses from human-facing
// channels (Slack, email, Reddit, web UI, etc.). Channels are values, not types
// behind interfaces — each "capability" (notify / await verdict / converse) is a
// function field on the Channel struct that may be nil to indicate the channel
// doesn't support that operation.
//
// The package is intentionally dependency-free at its core. Concrete adapters
// (e.g. channels/slack) and the Temporal binding (channels/temporal) live in
// subpackages and bring in only the dependencies they need.
package channels

import (
	"errors"
	"time"
)

// Severity is a coarse ordinal used for routing and rendering. Channels and
// routers interpret it; the package does not enforce semantics beyond ordering.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Rank returns a comparable integer for a Severity. Higher is more severe.
// Unknown severities rank as Info (0).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at or above the given threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s.Rank() >= threshold.Rank()
}

// Subject identifies what a Message is *about* — a finding, an incident, a PR.
// Adapters may use Subject.Kind for grouping or threading.
type Subject struct {
	Kind string // e.g. "finding", "incident", "pull-request"
	ID   string // domain-specific identifier
}

// Evidence is a single cited fact supporting the Message. Channels render it;
// they don't interpret it. Keep the schema permissive: agentic workflows produce
// heterogeneous evidence (file:line, commit, API field, log entry).
type Evidence struct {
	Kind        string            // "file", "commit", "api-field", "log", "url"
	Description string            // human-readable summary
	Location    string            // path / SHA / endpoint / timestamp / URL
	Attributes  map[string]string // adapter-specific extras
}

// Action describes a verdict choice offered to the human. Adapters render this
// as buttons, emoji prompts, reply commands, etc., according to channel idioms.
type Action struct {
	ID    string // stable identifier; matches Verdict.Choice
	Label string // human-facing text
	Style string // optional channel hint: "primary" / "danger" / "default"
}

// Link is an out-of-band hyperlink shown alongside the Message. Used for
// "Open in Temporal", "View Jira ticket", "See DAG", etc.
type Link struct {
	Label string
	URL   string
}

// WorkflowRef is the durable back-reference every Message carries. Channels MUST
// surface this somehow (link, footer, header) so that any human looking at the
// channel can navigate to the originating workflow's trace.
type WorkflowRef struct {
	WorkflowID string
	RunID      string
	TraceURL   string // pre-rendered link to Temporal Web UI when available
}

// Message is the canonical workflow → human payload. Channels render it through
// the Renderer seam; they do not own the message shape.
type Message struct {
	Subject     Subject
	Title       string
	Body        string
	Severity    Severity
	Evidence    []Evidence
	Actions     []Action
	Links       []Link
	WorkflowRef WorkflowRef

	// Target is set by the Dispatcher from Router output before the message
	// reaches the adapter. Adapters read this to know which channel-native
	// destination to use ("#security-findings", "ops@example.com", etc.).
	Target string

	// Metadata is the per-message escape hatch. Workflow code may set
	// channel-specific overrides here. Treat it as advisory; adapters may
	// ignore unrecognized keys.
	Metadata map[string]string
}

// Receipt is what an adapter returns after a successful Notify. It carries
// enough information to (a) display a deep link to the message, and (b) look
// the message up later for Await operations.
type Receipt struct {
	Channel  string         // which adapter handled it ("slack", "email", ...)
	ID       string         // channel-native message ID
	URL      string         // deep link, when available
	PostedAt time.Time
	Target   string         // resolved destination (e.g. resolved channel ID)
	Raw      map[string]any // adapter-specific, opaque to workflows
}

// Identity is the framework-neutral representation of a human actor. Channels
// produce Identity values for actors that interact with messages (reactions,
// replies, button clicks). The IdentityResolver seam controls how channel-native
// IDs are resolved into Identity values.
type Identity struct {
	Canonical string            // resolved canonical form, e.g. "okta:00u..." or "slack:U..."
	Display   string            // human-readable display name
	Email     string            // best join key when available
	Sources   map[string]string // all known channel-native IDs, by channel name
}

// Verdict is the workflow's typed view of a human's choice.
type Verdict struct {
	Choice  string    // matches an Action.ID from the originating Message
	Actor   Identity  // resolved via IdentityResolver
	At      time.Time // when the verdict was registered
	Comment string    // optional free-text from the human
	Channel string    // which channel produced it
}

// Reply is a single threaded reply to a Message, when the channel supports
// conversation. Workflows may treat replies as additional evidence.
type Reply struct {
	Actor   Identity
	At      time.Time
	Body    string
	Channel string
}

// AwaitOpts configures verdict / reply harvesting.
type AwaitOpts struct {
	Timeout    time.Duration
	Quorum     int        // minimum verdicts before returning; 0 means "first valid"
	Authorized []Identity // when non-empty, only these identities' verdicts count
	Options    []string   // when non-empty, only these Action.IDs count toward Quorum
}

// Sentinel errors returned by the Dispatcher and adapters.
var (
	ErrNoChannelSupportsAwait    = errors.New("channels: no notified channel supports Await")
	ErrNoChannelSupportsConverse = errors.New("channels: no notified channel supports Converse")
	ErrTimeout                   = errors.New("channels: await timed out before quorum")
	ErrUnknownChannel            = errors.New("channels: unknown channel for receipt")
	ErrNoTarget                  = errors.New("channels: router produced no destinations")
)
