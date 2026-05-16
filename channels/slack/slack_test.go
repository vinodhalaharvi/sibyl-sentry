package slack

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vinodhalaharvi/sibyl-sentry/channels"
)

// ---------------------------------------------------------------------------
// fakeClient implements Client for tests.
// ---------------------------------------------------------------------------

type fakeClient struct {
	mu sync.Mutex

	postErr     error
	postedOpts  []PostOptions
	postedChans []string
	postResult  PostResult

	reactions     [][]Reaction // scripted return values, popped front-to-back
	reactionsCall int
	reactionsErr  error

	threadReplies []ThreadMessage
	threadErr     error

	users map[string]UserProfile
}

func (f *fakeClient) PostMessage(_ context.Context, channelID string, opts PostOptions) (PostResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.postErr != nil {
		return PostResult{}, f.postErr
	}
	f.postedChans = append(f.postedChans, channelID)
	f.postedOpts = append(f.postedOpts, opts)
	if f.postResult.ChannelID == "" {
		return PostResult{
			ChannelID: channelID,
			Timestamp: "1700000000.000001",
		}, nil
	}
	return f.postResult, nil
}

func (f *fakeClient) GetReactions(_ context.Context, _ string, _ string) ([]Reaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reactionsErr != nil {
		return nil, f.reactionsErr
	}
	if f.reactionsCall < len(f.reactions) {
		r := f.reactions[f.reactionsCall]
		f.reactionsCall++
		return r, nil
	}
	return nil, nil
}

func (f *fakeClient) GetThreadReplies(_ context.Context, _ string, _ string) ([]ThreadMessage, error) {
	if f.threadErr != nil {
		return nil, f.threadErr
	}
	return f.threadReplies, nil
}

func (f *fakeClient) LookupUser(_ context.Context, userID string) (UserProfile, error) {
	if p, ok := f.users[userID]; ok {
		return p, nil
	}
	return UserProfile{ID: userID, DisplayName: userID}, nil
}

// ---------------------------------------------------------------------------
// Render tests
// ---------------------------------------------------------------------------

func TestDefaultRender_HasHeaderBodyEvidenceActions(t *testing.T) {
	m := channels.Message{
		Title:    "Stale OAuth",
		Body:     "Last used 1018 days ago.",
		Severity: channels.SeverityCritical,
		Evidence: []channels.Evidence{
			{Kind: "api-field", Description: "lastUsed", Location: "2023-08-01"},
		},
		Actions: []channels.Action{
			{ID: "accept", Label: "Accept", Style: "primary"},
			{ID: "reject", Label: "Reject", Style: "danger"},
		},
		Links: []channels.Link{
			{Label: "Open in Temporal", URL: "https://temporal.test/wf/1"},
		},
		WorkflowRef: channels.WorkflowRef{WorkflowID: "wf-1", TraceURL: "https://temporal.test/wf/1"},
	}
	opts := DefaultRender(m)

	if opts.Text == "" {
		t.Error("plain-text fallback should be populated")
	}
	if len(opts.Blocks) < 4 {
		t.Fatalf("expected at least 4 blocks (header/body/evidence/actions), got %d", len(opts.Blocks))
	}

	// Header must reference severity.
	if opts.Blocks[0].Kind != BlockHeader {
		t.Errorf("first block should be header, got %v", opts.Blocks[0].Kind)
	}
	if !strings.Contains(opts.Blocks[0].Text, "CRITICAL") {
		t.Errorf("header should include severity, got %q", opts.Blocks[0].Text)
	}

	// Find the actions block; it must contain a button for "accept" and a link button.
	var actions Block
	for _, b := range opts.Blocks {
		if b.Kind == BlockActions {
			actions = b
			break
		}
	}
	if len(actions.Buttons) < 3 {
		t.Fatalf("expected at least 3 buttons (accept/reject/link), got %d", len(actions.Buttons))
	}

	// Workflow back-reference must be present somewhere.
	found := false
	for _, b := range opts.Blocks {
		if b.Kind == BlockContext {
			for _, e := range b.Elements {
				if strings.Contains(e, "wf-1") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("workflow ID should appear in a context block")
	}
}

func TestDefaultRender_OmitsEmptySections(t *testing.T) {
	m := channels.Message{Title: "Just a title"}
	opts := DefaultRender(m)
	for _, b := range opts.Blocks {
		if b.Kind == BlockSection && b.Text == "" {
			t.Error("empty section block should not be emitted")
		}
		if b.Kind == BlockActions && len(b.Buttons) == 0 {
			t.Error("actions block with no buttons should not be emitted")
		}
	}
}

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNew_RequiresName(t *testing.T) {
	if _, err := New("", &fakeClient{}, Config{}); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestNew_RequiresClient(t *testing.T) {
	if _, err := New("slack", nil, Config{}); err == nil {
		t.Error("expected error for nil client")
	}
}

func TestNew_AppliesDefaults(t *testing.T) {
	ch, err := New("slack", &fakeClient{}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Name != "slack" {
		t.Errorf("Name = %q, want slack", ch.Name)
	}
	if ch.Notify == nil || ch.Await == nil || ch.Converse == nil {
		t.Error("all capability fns should be populated")
	}
}

// ---------------------------------------------------------------------------
// Notify
// ---------------------------------------------------------------------------

func TestNotify_PostsToTargetChannel(t *testing.T) {
	fc := &fakeClient{}
	ch, _ := New("slack", fc, Config{})
	r, err := ch.Notify(context.Background(), channels.Message{
		Title:  "hello",
		Target: "C0123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fc.postedChans) != 1 || fc.postedChans[0] != "C0123" {
		t.Errorf("posted to %v, want [C0123]", fc.postedChans)
	}
	if r.ID == "" {
		t.Error("receipt should have a Slack ts as ID")
	}
	cid, _ := r.Raw["channel_id"].(string)
	if cid != "C0123" {
		t.Errorf("receipt Raw[channel_id] = %q, want C0123", cid)
	}
}

func TestNotify_RequiresTarget(t *testing.T) {
	ch, _ := New("slack", &fakeClient{}, Config{})
	_, err := ch.Notify(context.Background(), channels.Message{Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "no target") {
		t.Errorf("expected no-target error, got %v", err)
	}
}

func TestNotify_PropagatesClientError(t *testing.T) {
	fc := &fakeClient{postErr: errors.New("rate limited")}
	ch, _ := New("slack", fc, Config{})
	_, err := ch.Notify(context.Background(), channels.Message{Target: "C1"})
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("expected wrapped client error, got %v", err)
	}
}

func TestNotify_CallsRenderer(t *testing.T) {
	called := false
	customRender := func(m channels.Message) PostOptions {
		called = true
		return PostOptions{Text: "rendered:" + m.Title}
	}
	fc := &fakeClient{}
	ch, _ := New("slack", fc, Config{Render: customRender})
	if _, err := ch.Notify(context.Background(), channels.Message{Title: "hi", Target: "C1"}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("custom renderer should have been invoked")
	}
	if fc.postedOpts[0].Text != "rendered:hi" {
		t.Errorf("renderer output not propagated: %+v", fc.postedOpts[0])
	}
}

// ---------------------------------------------------------------------------
// Await
// ---------------------------------------------------------------------------

func TestAwait_ReturnsVerdictOnMatchingReaction(t *testing.T) {
	fc := &fakeClient{
		reactions: [][]Reaction{
			{{Name: "white_check_mark", Users: []string{"U999"}, Count: 1}},
		},
	}
	ch, _ := New("slack", fc, Config{
		PollInterval:      time.Millisecond,
		VerdictByReaction: map[string]string{"white_check_mark": "accept"},
	})
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	v, err := ch.Await(context.Background(), r, channels.AwaitOpts{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if v.Choice != "accept" {
		t.Errorf("Choice = %q, want accept", v.Choice)
	}
	if v.Actor.Canonical != "slack:U999" {
		t.Errorf("Actor.Canonical = %q, want slack:U999", v.Actor.Canonical)
	}
	if v.Channel != "slack" {
		t.Errorf("Channel = %q, want slack", v.Channel)
	}
}

func TestAwait_TimesOut(t *testing.T) {
	fc := &fakeClient{
		// No reactions ever.
	}
	ch, _ := New("slack", fc, Config{
		PollInterval:      10 * time.Millisecond,
		VerdictByReaction: map[string]string{"x": "y"},
	})
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	start := time.Now()
	_, err := ch.Await(context.Background(), r, channels.AwaitOpts{Timeout: 50 * time.Millisecond})
	if !errors.Is(err, channels.ErrTimeout) {
		t.Errorf("expected ErrTimeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Errorf("Await returned too fast: %v", elapsed)
	}
}

func TestAwait_RequiresVerdictMapping(t *testing.T) {
	ch, _ := New("slack", &fakeClient{}, Config{}) // no VerdictByReaction
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	_, err := ch.Await(context.Background(), r, channels.AwaitOpts{Timeout: time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "VerdictByReaction") {
		t.Errorf("expected config error, got %v", err)
	}
}

func TestAwait_IgnoresUnmappedReactions(t *testing.T) {
	fc := &fakeClient{
		reactions: [][]Reaction{
			{{Name: "thumbsdown", Users: []string{"U1"}, Count: 1}},
			{{Name: "white_check_mark", Users: []string{"U2"}, Count: 1}},
		},
	}
	ch, _ := New("slack", fc, Config{
		PollInterval:      time.Millisecond,
		VerdictByReaction: map[string]string{"white_check_mark": "accept"},
	})
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	v, err := ch.Await(context.Background(), r, channels.AwaitOpts{Timeout: time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Choice != "accept" {
		t.Errorf("expected accept after unmapped reaction was ignored, got %q", v.Choice)
	}
}

func TestAwait_OptionsFilterChoices(t *testing.T) {
	fc := &fakeClient{
		reactions: [][]Reaction{
			{{Name: "white_check_mark", Users: []string{"U1"}, Count: 1}},
			{{Name: "x", Users: []string{"U2"}, Count: 1}},
		},
	}
	ch, _ := New("slack", fc, Config{
		PollInterval: time.Millisecond,
		VerdictByReaction: map[string]string{
			"white_check_mark": "accept",
			"x":                "reject",
		},
	})
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	// Restrict to "reject" only — accept reactions should be ignored.
	v, err := ch.Await(context.Background(), r, channels.AwaitOpts{
		Timeout: 500 * time.Millisecond,
		Options: []string{"reject"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Choice != "reject" {
		t.Errorf("expected reject, got %q", v.Choice)
	}
}

func TestAwait_AuthorizedFilter(t *testing.T) {
	fc := &fakeClient{
		reactions: [][]Reaction{
			{{Name: "ok", Users: []string{"U_RANDOM", "U_AUTHORIZED"}, Count: 2}},
		},
	}
	ch, _ := New("slack", fc, Config{
		PollInterval:      time.Millisecond,
		VerdictByReaction: map[string]string{"ok": "accept"},
	})
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	v, err := ch.Await(context.Background(), r, channels.AwaitOpts{
		Timeout: time.Second,
		Authorized: []channels.Identity{
			{Sources: map[string]string{"slack": "U_AUTHORIZED"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Actor.Canonical != "slack:U_AUTHORIZED" {
		t.Errorf("expected authorized user to win, got %q", v.Actor.Canonical)
	}
}

func TestAwait_ContextCancellation(t *testing.T) {
	fc := &fakeClient{} // no reactions
	ch, _ := New("slack", fc, Config{
		PollInterval:      100 * time.Millisecond,
		VerdictByReaction: map[string]string{"x": "y"},
	})
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := ch.Await(ctx, r, channels.AwaitOpts{Timeout: time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Converse
// ---------------------------------------------------------------------------

func TestConverse_SkipsParent(t *testing.T) {
	fc := &fakeClient{
		threadReplies: []ThreadMessage{
			{IsParent: true, User: "U_BOT", Text: "original post", Timestamp: "1700000000.000001"},
			{User: "U1", Text: "first reply", Timestamp: "1700000001.000000"},
			{User: "U2", Text: "second reply", Timestamp: "1700000002.000000"},
		},
	}
	ch, _ := New("slack", fc, Config{})
	r := channels.Receipt{Channel: "slack", Raw: map[string]any{"channel_id": "C1", "ts": "1.1"}}
	replies, err := ch.Converse(context.Background(), r, channels.AwaitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 2 {
		t.Fatalf("expected 2 replies (parent skipped), got %d", len(replies))
	}
	if replies[0].Body != "first reply" || replies[1].Body != "second reply" {
		t.Errorf("bodies wrong: %+v", replies)
	}
	if replies[0].Actor.Canonical != "slack:U1" {
		t.Errorf("Actor.Canonical = %q, want slack:U1", replies[0].Actor.Canonical)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestParseSlackTimestamp(t *testing.T) {
	tm, err := parseSlackTimestamp("1700000000.000123")
	if err != nil {
		t.Fatal(err)
	}
	if tm.Unix() != 1700000000 {
		t.Errorf("Unix = %d, want 1700000000", tm.Unix())
	}
	if _, err := parseSlackTimestamp("bad"); err == nil {
		t.Error("expected error for non-numeric timestamp")
	}
}

func TestExtractMessageID_PrefersRaw(t *testing.T) {
	r := channels.Receipt{
		Target: "T_fallback",
		ID:     "ID_fallback",
		Raw:    map[string]any{"channel_id": "C_real", "ts": "1.0"},
	}
	cid, ts, ok := extractMessageID(r)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cid != "C_real" || ts != "1.0" {
		t.Errorf("got %s/%s, want C_real/1.0", cid, ts)
	}
}

func TestExtractMessageID_FallsBackToTopLevel(t *testing.T) {
	r := channels.Receipt{Target: "C_top", ID: "1.2"}
	cid, ts, ok := extractMessageID(r)
	if !ok || cid != "C_top" || ts != "1.2" {
		t.Errorf("fallback path broken: %s/%s ok=%v", cid, ts, ok)
	}
}
