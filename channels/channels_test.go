package channels

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers — fake channels for testing
// ---------------------------------------------------------------------------

// fakeChannel returns a Channel whose Notify records the messages it received
// and returns a Receipt referencing them by index. Await returns a fixed
// Verdict (or err) on each call. Converse returns fixed Replies.
type fakeChannel struct {
	name     string
	posted   []Message
	notifyErr error
	verdict  Verdict
	awaitErr error
	replies  []Reply
}

func (f *fakeChannel) channel() Channel {
	ch := Channel{Name: f.name}
	ch.Notify = func(ctx context.Context, m Message) (Receipt, error) {
		if f.notifyErr != nil {
			return Receipt{}, f.notifyErr
		}
		f.posted = append(f.posted, m)
		return Receipt{
			Channel:  f.name,
			ID:       "msg-" + f.name,
			Target:   m.Target,
			PostedAt: time.Now(),
		}, nil
	}
	if f.verdict.Choice != "" || f.awaitErr != nil {
		ch.Await = func(ctx context.Context, r Receipt, opts AwaitOpts) (Verdict, error) {
			if f.awaitErr != nil {
				return Verdict{}, f.awaitErr
			}
			return f.verdict, nil
		}
	}
	if f.replies != nil {
		ch.Converse = func(ctx context.Context, r Receipt, opts AwaitOpts) ([]Reply, error) {
			return f.replies, nil
		}
	}
	return ch
}

func sampleMessage(severity Severity) Message {
	return Message{
		Subject:  Subject{Kind: "finding", ID: "f-1"},
		Title:    "OAuth client stale",
		Severity: severity,
		Evidence: []Evidence{{
			Kind:     "api-field",
			Location: "oktaclient.lastUsed",
		}},
		Actions: []Action{
			{ID: "accept", Label: "Accept"},
			{ID: "reject", Label: "Reject"},
		},
		WorkflowRef: WorkflowRef{WorkflowID: "wf-1"},
	}
}

// ---------------------------------------------------------------------------
// Severity tests
// ---------------------------------------------------------------------------

func TestSeverity_Rank(t *testing.T) {
	cases := []struct {
		s    Severity
		rank int
	}{
		{SeverityInfo, 0},
		{SeverityLow, 1},
		{SeverityMedium, 2},
		{SeverityHigh, 3},
		{SeverityCritical, 4},
		{Severity("UNKNOWN"), 0},
	}
	for _, tc := range cases {
		if got := tc.s.Rank(); got != tc.rank {
			t.Errorf("Severity(%q).Rank() = %d, want %d", tc.s, got, tc.rank)
		}
	}
}

func TestSeverity_AtLeast(t *testing.T) {
	if !SeverityHigh.AtLeast(SeverityMedium) {
		t.Errorf("HIGH should be at least MEDIUM")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Errorf("LOW should not be at least HIGH")
	}
	if !SeverityCritical.AtLeast(SeverityCritical) {
		t.Errorf("CRITICAL should be at least CRITICAL")
	}
}

// ---------------------------------------------------------------------------
// PassthroughResolver
// ---------------------------------------------------------------------------

func TestPassthroughResolver(t *testing.T) {
	id, err := PassthroughResolver(context.Background(), "slack", "U123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Canonical != "slack:U123" {
		t.Errorf("Canonical = %q, want slack:U123", id.Canonical)
	}
	if id.Sources["slack"] != "U123" {
		t.Errorf("Sources[slack] = %q, want U123", id.Sources["slack"])
	}
}

// ---------------------------------------------------------------------------
// Router tests
// ---------------------------------------------------------------------------

func TestFixedRouter(t *testing.T) {
	r := FixedRouter("slack", "#general")
	dests := r(sampleMessage(SeverityInfo))
	if len(dests) != 1 || dests[0].Channel != "slack" || dests[0].Target != "#general" {
		t.Errorf("FixedRouter produced %v", dests)
	}
}

func TestSeverityRouter_DropsBelowThreshold(t *testing.T) {
	r := SeverityRouter("slack", "#findings", SeverityHigh, nil)
	if got := r(sampleMessage(SeverityMedium)); got != nil {
		t.Errorf("expected nil destinations for MEDIUM < HIGH threshold, got %v", got)
	}
}

func TestSeverityRouter_SeverityOverride(t *testing.T) {
	r := SeverityRouter(
		"slack", "#findings",
		SeverityMedium,
		map[Severity]Destination{
			SeverityCritical: {Channel: "slack", Target: "#incidents"},
		},
	)
	dests := r(sampleMessage(SeverityCritical))
	if len(dests) != 1 || dests[0].Target != "#incidents" {
		t.Errorf("CRITICAL should route to #incidents, got %v", dests)
	}
	dests = r(sampleMessage(SeverityHigh))
	if len(dests) != 1 || dests[0].Target != "#findings" {
		t.Errorf("HIGH should fall through to default, got %v", dests)
	}
}

func TestMultiRouter(t *testing.T) {
	r := MultiRouter(
		FixedRouter("slack", "#a"),
		FixedRouter("email", "ops@example.com"),
	)
	dests := r(sampleMessage(SeverityHigh))
	if len(dests) != 2 {
		t.Fatalf("expected 2 destinations, got %d", len(dests))
	}
	if dests[0].Channel != "slack" || dests[1].Channel != "email" {
		t.Errorf("MultiRouter order wrong: %v", dests)
	}
}

// ---------------------------------------------------------------------------
// Dispatcher construction
// ---------------------------------------------------------------------------

func TestNew_RequiresRouter(t *testing.T) {
	fc := &fakeChannel{name: "slack"}
	_, err := New(WithChannel(fc.channel()))
	if err == nil {
		t.Fatal("expected error when no router is configured")
	}
}

func TestNew_RequiresAtLeastOneChannel(t *testing.T) {
	_, err := New(WithRouter(FixedRouter("slack", "#a")))
	if err == nil {
		t.Fatal("expected error when no channels are configured")
	}
}

func TestNew_RejectsNilNotify(t *testing.T) {
	bad := Channel{Name: "broken"} // Notify is nil
	_, err := New(
		WithRouter(FixedRouter("broken", "x")),
		WithChannel(bad),
	)
	if err == nil {
		t.Fatal("expected error when channel has nil Notify")
	}
}

func TestNew_IgnoresChannelWithEmptyName(t *testing.T) {
	fc := &fakeChannel{name: "real"}
	_, err := New(
		WithRouter(FixedRouter("real", "x")),
		WithChannel(Channel{}), // ignored
		WithChannel(fc.channel()),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

func TestSend_HappyPath(t *testing.T) {
	fc := &fakeChannel{name: "slack"}
	d, err := New(
		WithRouter(FixedRouter("slack", "#findings")),
		WithChannel(fc.channel()),
	)
	if err != nil {
		t.Fatal(err)
	}
	receipts, errs := d.Send(context.Background(), sampleMessage(SeverityHigh))
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Channel != "slack" || receipts[0].Target != "#findings" {
		t.Errorf("receipt channel/target wrong: %+v", receipts[0])
	}
	if len(fc.posted) != 1 || fc.posted[0].Target != "#findings" {
		t.Errorf("posted message target wrong: %+v", fc.posted)
	}
}

func TestSend_FansOutAcrossDestinations(t *testing.T) {
	slack := &fakeChannel{name: "slack"}
	email := &fakeChannel{name: "email"}
	d, _ := New(
		WithRouter(MultiRouter(
			FixedRouter("slack", "#a"),
			FixedRouter("email", "x@y.com"),
		)),
		WithChannel(slack.channel()),
		WithChannel(email.channel()),
	)
	receipts, errs := d.Send(context.Background(), sampleMessage(SeverityHigh))
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(receipts))
	}
	if len(slack.posted) != 1 || len(email.posted) != 1 {
		t.Errorf("each channel should have 1 message; slack=%d email=%d",
			len(slack.posted), len(email.posted))
	}
}

func TestSend_PerDestinationTargetIsolation(t *testing.T) {
	// Same channel, two targets. Ensure the second post sees target "#b",
	// not the leaked "#a" from the first.
	fc := &fakeChannel{name: "slack"}
	d, _ := New(
		WithRouter(MultiRouter(
			FixedRouter("slack", "#a"),
			FixedRouter("slack", "#b"),
		)),
		WithChannel(fc.channel()),
	)
	d.Send(context.Background(), sampleMessage(SeverityHigh))
	if len(fc.posted) != 2 {
		t.Fatalf("expected 2 posts, got %d", len(fc.posted))
	}
	if fc.posted[0].Target != "#a" || fc.posted[1].Target != "#b" {
		t.Errorf("target isolation failed: %q, %q",
			fc.posted[0].Target, fc.posted[1].Target)
	}
}

func TestSend_NoDestinationsReturnsError(t *testing.T) {
	fc := &fakeChannel{name: "slack"}
	// Severity router drops MEDIUM when threshold is HIGH → no destinations.
	d, _ := New(
		WithRouter(SeverityRouter("slack", "#x", SeverityHigh, nil)),
		WithChannel(fc.channel()),
	)
	_, errs := d.Send(context.Background(), sampleMessage(SeverityMedium))
	if len(errs) != 1 || !errors.Is(errs[0], ErrNoTarget) {
		t.Errorf("expected ErrNoTarget, got %v", errs)
	}
}

func TestSend_UnknownChannelReportedAsError(t *testing.T) {
	fc := &fakeChannel{name: "slack"}
	d, _ := New(
		WithRouter(FixedRouter("teams", "#x")),
		WithChannel(fc.channel()),
	)
	_, errs := d.Send(context.Background(), sampleMessage(SeverityHigh))
	if len(errs) != 1 || !errors.Is(errs[0], ErrUnknownChannel) {
		t.Errorf("expected ErrUnknownChannel, got %v", errs)
	}
}

func TestSend_PerChannelFailureDoesNotAbortOthers(t *testing.T) {
	good := &fakeChannel{name: "good"}
	bad := &fakeChannel{name: "bad", notifyErr: errors.New("boom")}
	d, _ := New(
		WithRouter(MultiRouter(
			FixedRouter("bad", "x"),
			FixedRouter("good", "y"),
		)),
		WithChannel(good.channel()),
		WithChannel(bad.channel()),
	)
	receipts, errs := d.Send(context.Background(), sampleMessage(SeverityHigh))
	if len(receipts) != 1 || receipts[0].Channel != "good" {
		t.Errorf("expected one receipt from good channel, got %v", receipts)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "boom") {
		t.Errorf("expected one wrapped error, got %v", errs)
	}
}

// ---------------------------------------------------------------------------
// AwaitVerdict
// ---------------------------------------------------------------------------

func TestAwaitVerdict_FirstAwaitableWins(t *testing.T) {
	verdictCh := &fakeChannel{name: "slack", verdict: Verdict{Choice: "accept"}}
	d, _ := New(
		WithRouter(FixedRouter("slack", "#x")),
		WithChannel(verdictCh.channel()),
	)
	receipts, _ := d.Send(context.Background(), sampleMessage(SeverityHigh))
	v, err := d.AwaitVerdict(context.Background(), receipts, AwaitOpts{Timeout: time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Choice != "accept" {
		t.Errorf("Choice = %q, want accept", v.Choice)
	}
	if v.Channel != "slack" {
		t.Errorf("Channel = %q, want slack", v.Channel)
	}
}

func TestAwaitVerdict_NoCapableChannel(t *testing.T) {
	notifyOnly := &fakeChannel{name: "email"} // no verdict configured → Await nil
	d, _ := New(
		WithRouter(FixedRouter("email", "x")),
		WithChannel(notifyOnly.channel()),
	)
	receipts, _ := d.Send(context.Background(), sampleMessage(SeverityHigh))
	_, err := d.AwaitVerdict(context.Background(), receipts, AwaitOpts{})
	if !errors.Is(err, ErrNoChannelSupportsAwait) {
		t.Errorf("expected ErrNoChannelSupportsAwait, got %v", err)
	}
}

func TestAwaitVerdict_FailsOver(t *testing.T) {
	// First receipt errors; second succeeds.
	failing := &fakeChannel{name: "fails", awaitErr: errors.New("boom")}
	winning := &fakeChannel{name: "wins", verdict: Verdict{Choice: "accept"}}
	d, _ := New(
		WithRouter(MultiRouter(
			FixedRouter("fails", "x"),
			FixedRouter("wins", "y"),
		)),
		WithChannel(failing.channel()),
		WithChannel(winning.channel()),
	)
	receipts, _ := d.Send(context.Background(), sampleMessage(SeverityHigh))
	v, err := d.AwaitVerdict(context.Background(), receipts, AwaitOpts{})
	if err != nil {
		t.Fatalf("expected failover to succeed, got %v", err)
	}
	if v.Choice != "accept" || v.Channel != "wins" {
		t.Errorf("unexpected verdict: %+v", v)
	}
}

// ---------------------------------------------------------------------------
// AwaitReplies
// ---------------------------------------------------------------------------

func TestAwaitReplies_ConcatenatesAcrossChannels(t *testing.T) {
	a := &fakeChannel{name: "a", replies: []Reply{{Body: "from-a", Channel: "a"}}}
	b := &fakeChannel{name: "b", replies: []Reply{{Body: "from-b", Channel: "b"}}}
	d, _ := New(
		WithRouter(MultiRouter(
			FixedRouter("a", "x"),
			FixedRouter("b", "y"),
		)),
		WithChannel(a.channel()),
		WithChannel(b.channel()),
	)
	receipts, _ := d.Send(context.Background(), sampleMessage(SeverityHigh))
	replies, err := d.AwaitReplies(context.Background(), receipts, AwaitOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(replies) != 2 {
		t.Errorf("expected 2 replies, got %d: %v", len(replies), replies)
	}
}

func TestAwaitReplies_NoCapableChannel(t *testing.T) {
	fc := &fakeChannel{name: "slack"} // no replies → Converse nil
	d, _ := New(
		WithRouter(FixedRouter("slack", "#x")),
		WithChannel(fc.channel()),
	)
	receipts, _ := d.Send(context.Background(), sampleMessage(SeverityHigh))
	_, err := d.AwaitReplies(context.Background(), receipts, AwaitOpts{})
	if !errors.Is(err, ErrNoChannelSupportsConverse) {
		t.Errorf("expected ErrNoChannelSupportsConverse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ChannelNames
// ---------------------------------------------------------------------------

func TestChannelNames(t *testing.T) {
	a := &fakeChannel{name: "a"}
	b := &fakeChannel{name: "b"}
	d, _ := New(
		WithRouter(FixedRouter("a", "x")),
		WithChannel(a.channel()),
		WithChannel(b.channel()),
	)
	names := d.ChannelNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d: %v", len(names), names)
	}
}
