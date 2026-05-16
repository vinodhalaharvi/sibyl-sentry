// Package slack provides a channels adapter for Slack workspaces. It depends
// on github.com/slack-go/slack via a small abstraction (Client) so that tests
// can substitute a fake without bringing in the real library.
package slack

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/channels"
)

// ---------------------------------------------------------------------------
// Client abstraction
//
// The full slack-go API is large; the adapter only needs a tiny slice of it.
// Defining the slice here as an interface makes the adapter trivially testable
// and decouples it from any specific slack-go version.
// ---------------------------------------------------------------------------

// Client is the slim subset of the slack-go client surface this adapter uses.
// A concrete implementation backed by *slack.Client lives in slack_real.go (a
// build-tag-gated file in production); tests use FakeClient from slack_test.go.
type Client interface {
	// PostMessage posts a message and returns the resulting channel ID and
	// timestamp. The opts argument is a free-form payload (Block Kit JSON,
	// thread_ts, etc.) — the adapter passes whatever the renderer produced.
	PostMessage(ctx context.Context, channelID string, opts PostOptions) (PostResult, error)

	// GetReactions returns all reactions currently on the given message.
	GetReactions(ctx context.Context, channelID string, timestamp string) ([]Reaction, error)

	// GetThreadReplies returns the parent message followed by all threaded
	// replies. The first element is the parent; index 0 should be skipped by
	// callers when collecting replies.
	GetThreadReplies(ctx context.Context, channelID string, parentTS string) ([]ThreadMessage, error)

	// LookupUser returns profile information for a Slack user ID. Used by the
	// adapter to seed Identity values before delegating to IdentityResolver.
	LookupUser(ctx context.Context, userID string) (UserProfile, error)
}

// PostOptions is the channel-agnostic payload passed to Client.PostMessage.
// The Blocks field carries the rendered Block Kit; ThreadTS, if non-empty,
// posts the message as a reply.
type PostOptions struct {
	Blocks   []Block
	Text     string // fallback plain text for notifications and accessibility
	ThreadTS string // when posting in a thread
}

// PostResult is the slim return type of PostMessage.
type PostResult struct {
	ChannelID string
	Timestamp string // Slack message identifier within a channel
	Permalink string // populated when the client can resolve it
}

// Reaction is one emoji reaction on a message.
type Reaction struct {
	Name  string   // emoji shortcode without colons, e.g. "white_check_mark"
	Users []string // Slack user IDs that reacted
	Count int
}

// ThreadMessage is a single message in a thread (parent or reply).
type ThreadMessage struct {
	User      string
	Text      string
	Timestamp string
	IsParent  bool
}

// UserProfile is the minimal user information used for identity resolution.
type UserProfile struct {
	ID          string
	DisplayName string
	Email       string
}

// ---------------------------------------------------------------------------
// Block Kit minimal types
//
// We deliberately do not wrap the full Block Kit schema. The adapter's default
// renderer builds simple section + actions + context blocks; consumers who
// want richer layouts override the renderer entirely and emit whatever the
// real slack-go library supports.
// ---------------------------------------------------------------------------

// BlockKind enumerates the small set of block types this adapter builds.
type BlockKind string

const (
	BlockSection BlockKind = "section"
	BlockDivider BlockKind = "divider"
	BlockContext BlockKind = "context"
	BlockActions BlockKind = "actions"
	BlockHeader  BlockKind = "header"
)

// Block is a render-target structure. It is not byte-for-byte the Block Kit
// JSON; the real client adapter is responsible for converting Block values
// into slack-go Block types before transmission.
type Block struct {
	Kind     BlockKind
	Text     string   // for section / header / context (markdown allowed in section/context)
	Buttons  []Button // for actions
	Elements []string // for context: small inline strings (e.g. severity tag)
}

// Button is a render-target representation of a Block Kit button.
type Button struct {
	ActionID string
	Label    string
	URL      string // when set, this is a link button; otherwise an interactive button
	Style    string // "primary" / "danger" / "" (default)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config configures the Slack adapter. Fields are validated in New.
type Config struct {
	// PollInterval controls how frequently the Await closure polls for new
	// reactions. Defaults to 5 seconds. Lower values produce faster verdicts
	// at the cost of more Slack API calls.
	PollInterval time.Duration

	// VerdictByReaction maps emoji shortcodes (without colons) to Action IDs.
	// Reactions not present in this map are ignored during Await.
	VerdictByReaction map[string]string

	// Resolver controls how Slack user IDs are converted into channels.Identity
	// values. Defaults to channels.PassthroughResolver. Override to bridge
	// Slack identities to Okta.
	Resolver channels.IdentityResolver

	// Render overrides the default message renderer. When nil, DefaultRender
	// is used.
	Render Renderer
}

// Renderer converts a channels.Message into the Slack-native render target.
type Renderer func(m channels.Message) PostOptions

// ---------------------------------------------------------------------------
// Default renderer
// ---------------------------------------------------------------------------

// DefaultRender produces a Block Kit layout suitable for hackathon-grade
// finding cards. Layout:
//
//	header  : "[SEVERITY] Title"
//	section : Body
//	context : Evidence list (one element per item, truncated)
//	actions : Buttons for each Action; link buttons for each Link
//	context : "Workflow: <id> — Open in Temporal"
func DefaultRender(m channels.Message) PostOptions {
	var blocks []Block

	// Header
	if m.Title != "" {
		title := m.Title
		if m.Severity != "" {
			title = fmt.Sprintf("[%s] %s", m.Severity, m.Title)
		}
		blocks = append(blocks, Block{Kind: BlockHeader, Text: title})
	}

	// Body
	if m.Body != "" {
		blocks = append(blocks, Block{Kind: BlockSection, Text: m.Body})
	}

	// Evidence
	if len(m.Evidence) > 0 {
		var elems []string
		for _, e := range m.Evidence {
			label := e.Description
			if label == "" {
				label = e.Location
			}
			if e.Kind != "" {
				label = fmt.Sprintf("%s: %s", e.Kind, label)
			}
			elems = append(elems, label)
		}
		blocks = append(blocks, Block{Kind: BlockContext, Elements: elems})
	}

	// Actions and links
	if len(m.Actions) > 0 || len(m.Links) > 0 {
		var buttons []Button
		for _, a := range m.Actions {
			buttons = append(buttons, Button{
				ActionID: a.ID,
				Label:    a.Label,
				Style:    a.Style,
			})
		}
		for _, l := range m.Links {
			buttons = append(buttons, Button{
				Label: l.Label,
				URL:   l.URL,
			})
		}
		blocks = append(blocks, Block{Kind: BlockActions, Buttons: buttons})
	}

	// Workflow back-reference
	if m.WorkflowRef.WorkflowID != "" {
		ref := fmt.Sprintf("Workflow: `%s`", m.WorkflowRef.WorkflowID)
		if m.WorkflowRef.TraceURL != "" {
			ref += " — <" + m.WorkflowRef.TraceURL + "|Open in Temporal>"
		}
		blocks = append(blocks, Block{Kind: BlockContext, Elements: []string{ref}})
	}

	// Plain-text fallback for notification previews.
	text := m.Title
	if text == "" {
		text = m.Body
	}
	return PostOptions{Blocks: blocks, Text: text}
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

// New constructs a channels.Channel backed by the given Slack Client. The
// returned Channel implements Notify, Await, and Converse capabilities.
func New(name string, client Client, cfg Config) (channels.Channel, error) {
	if name == "" {
		return channels.Channel{}, errors.New("slack: channel name is required")
	}
	if client == nil {
		return channels.Channel{}, errors.New("slack: client is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.Resolver == nil {
		cfg.Resolver = channels.PassthroughResolver
	}
	if cfg.Render == nil {
		cfg.Render = DefaultRender
	}

	return channels.Channel{
		Name:     name,
		Notify:   notifyFunc(name, client, cfg),
		Await:    awaitFunc(name, client, cfg),
		Converse: converseFunc(name, client, cfg),
	}, nil
}

// ---------------------------------------------------------------------------
// Capability implementations
// ---------------------------------------------------------------------------

func notifyFunc(name string, client Client, cfg Config) channels.Notify {
	return func(ctx context.Context, m channels.Message) (channels.Receipt, error) {
		if m.Target == "" {
			return channels.Receipt{}, errors.New("slack: message has no target channel")
		}
		opts := cfg.Render(m)
		res, err := client.PostMessage(ctx, m.Target, opts)
		if err != nil {
			return channels.Receipt{}, fmt.Errorf("slack: post: %w", err)
		}
		return channels.Receipt{
			Channel:  name,
			ID:       res.Timestamp,
			URL:      res.Permalink,
			Target:   res.ChannelID,
			PostedAt: time.Now(),
			Raw: map[string]any{
				"channel_id": res.ChannelID,
				"ts":         res.Timestamp,
			},
		}, nil
	}
}

func awaitFunc(name string, client Client, cfg Config) channels.Await {
	return func(ctx context.Context, r channels.Receipt, opts channels.AwaitOpts) (channels.Verdict, error) {
		if len(cfg.VerdictByReaction) == 0 {
			return channels.Verdict{}, errors.New("slack: no VerdictByReaction mapping configured")
		}
		channelID, ts, ok := extractMessageID(r)
		if !ok {
			return channels.Verdict{}, errors.New("slack: receipt missing channel_id/ts")
		}

		deadline := time.Now().Add(opts.Timeout)
		if opts.Timeout <= 0 {
			deadline = time.Now().Add(time.Hour)
		}
		authorized := identitySet(opts.Authorized, name)
		validChoices := stringSet(opts.Options)

		for {
			reactions, err := client.GetReactions(ctx, channelID, ts)
			if err == nil {
				if v, found := selectVerdict(ctx, name, client, cfg, reactions, authorized, validChoices); found {
					return v, nil
				}
			}
			if time.Now().After(deadline) {
				return channels.Verdict{}, channels.ErrTimeout
			}
			select {
			case <-ctx.Done():
				return channels.Verdict{}, ctx.Err()
			case <-time.After(cfg.PollInterval):
			}
		}
	}
}

func converseFunc(name string, client Client, cfg Config) channels.Converse {
	return func(ctx context.Context, r channels.Receipt, opts channels.AwaitOpts) ([]channels.Reply, error) {
		channelID, ts, ok := extractMessageID(r)
		if !ok {
			return nil, errors.New("slack: receipt missing channel_id/ts")
		}
		msgs, err := client.GetThreadReplies(ctx, channelID, ts)
		if err != nil {
			return nil, fmt.Errorf("slack: thread replies: %w", err)
		}
		var out []channels.Reply
		for _, msg := range msgs {
			if msg.IsParent {
				continue
			}
			id, err := cfg.Resolver(ctx, name, msg.User)
			if err != nil {
				// Identity unresolved — still record the reply with whatever
				// information we have.
				id = channels.Identity{
					Canonical: name + ":" + msg.User,
					Display:   msg.User,
					Sources:   map[string]string{name: msg.User},
				}
			}
			at, _ := parseSlackTimestamp(msg.Timestamp)
			out = append(out, channels.Reply{
				Actor:   id,
				At:      at,
				Body:    msg.Text,
				Channel: name,
			})
		}
		return out, nil
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func extractMessageID(r channels.Receipt) (channelID, ts string, ok bool) {
	if r.Raw == nil {
		// Fall back to Target + ID if Raw wasn't populated (defensive).
		if r.Target != "" && r.ID != "" {
			return r.Target, r.ID, true
		}
		return "", "", false
	}
	cid, _ := r.Raw["channel_id"].(string)
	mts, _ := r.Raw["ts"].(string)
	if cid == "" {
		cid = r.Target
	}
	if mts == "" {
		mts = r.ID
	}
	return cid, mts, cid != "" && mts != ""
}

// selectVerdict scans reactions for the first that maps to a valid verdict
// and was placed by an authorized user. Returns (verdict, true) when found.
func selectVerdict(
	ctx context.Context,
	channelName string,
	client Client,
	cfg Config,
	reactions []Reaction,
	authorized map[string]struct{},
	validChoices map[string]struct{},
) (channels.Verdict, bool) {
	for _, reaction := range reactions {
		choice, ok := cfg.VerdictByReaction[reaction.Name]
		if !ok {
			continue
		}
		if len(validChoices) > 0 {
			if _, allowed := validChoices[choice]; !allowed {
				continue
			}
		}
		// First authorized user that reacted wins. We iterate Users in order
		// so behavior is deterministic for tests.
		for _, uid := range reaction.Users {
			identity, err := cfg.Resolver(ctx, channelName, uid)
			if err != nil {
				continue
			}
			if !isAuthorized(authorized, identity) {
				continue
			}
			return channels.Verdict{
				Choice:  choice,
				Actor:   identity,
				At:      time.Now(),
				Channel: channelName,
			}, true
		}
	}
	return channels.Verdict{}, false
}

// identitySet builds a lookup of canonical-or-source-keyed identities. Empty
// input means "anyone authorized."
func identitySet(ids []channels.Identity, channelName string) map[string]struct{} {
	if len(ids) == 0 {
		return nil
	}
	out := map[string]struct{}{}
	for _, id := range ids {
		if id.Canonical != "" {
			out[id.Canonical] = struct{}{}
		}
		if src, ok := id.Sources[channelName]; ok {
			out[channelName+":"+src] = struct{}{}
		}
	}
	return out
}

func isAuthorized(set map[string]struct{}, id channels.Identity) bool {
	if set == nil {
		return true
	}
	if _, ok := set[id.Canonical]; ok {
		return true
	}
	for ch, src := range id.Sources {
		if _, ok := set[ch+":"+src]; ok {
			return true
		}
	}
	return false
}

func stringSet(xs []string) map[string]struct{} {
	if len(xs) == 0 {
		return nil
	}
	out := map[string]struct{}{}
	for _, x := range xs {
		out[x] = struct{}{}
	}
	return out
}

// parseSlackTimestamp parses a Slack message timestamp "1700000000.000123"
// into a time.Time. Returns zero time on parse error (caller's choice).
func parseSlackTimestamp(ts string) (time.Time, error) {
	parts := strings.SplitN(ts, ".", 2)
	if len(parts) == 0 || parts[0] == "" {
		return time.Time{}, fmt.Errorf("slack: bad timestamp %q", ts)
	}
	var sec int64
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return time.Time{}, fmt.Errorf("slack: bad timestamp %q", ts)
		}
		sec = sec*10 + int64(c-'0')
	}
	return time.Unix(sec, 0), nil
}
