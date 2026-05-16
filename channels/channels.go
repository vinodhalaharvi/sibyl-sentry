package channels

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Capability function types
//
// A Channel is a struct whose fields are functions implementing capabilities.
// Each field may be nil to indicate the channel does not support that
// capability. The compiler enforces signatures; the Dispatcher checks for nil.
// ---------------------------------------------------------------------------

// Notify sends a Message and returns a Receipt that can be used for later
// Await operations. Required for any usable Channel.
type Notify func(ctx context.Context, m Message) (Receipt, error)

// Await blocks until a Verdict is collected for the given Receipt, or until
// opts.Timeout elapses. Optional capability; channels that cannot solicit
// verdicts leave this nil.
type Await func(ctx context.Context, r Receipt, opts AwaitOpts) (Verdict, error)

// Converse collects threaded replies to the given Receipt. Optional capability.
type Converse func(ctx context.Context, r Receipt, opts AwaitOpts) ([]Reply, error)

// Channel bundles the capabilities a concrete adapter provides. Adapters expose
// a constructor (e.g. slack.New(...)) that returns a populated Channel value.
type Channel struct {
	Name     string
	Notify   Notify
	Await    Await
	Converse Converse
}

// ---------------------------------------------------------------------------
// Seams — pure-function configuration points
// ---------------------------------------------------------------------------

// Router selects which channels and targets a Message should reach.
// Routers are pure functions; multiple destinations may be returned and the
// Dispatcher will fan out to each.
type Router func(m Message) []Destination

// Destination names a channel and a channel-native target (e.g. a Slack
// channel ID, an email address).
type Destination struct {
	Channel string
	Target  string
}

// Renderer converts a Message into a channel-native payload type T. Adapters
// ship a default Renderer and accept overrides from consumers.
//
// Renderer is not used by the core Dispatcher; it is referenced by adapters
// in their own packages, expressed here purely as documentation of the seam
// pattern. Generics live with the adapter.

// IdentityResolver maps a channel-native user ID into the framework's Identity
// value. The default PassthroughResolver namespaces the native ID and produces
// a usable Identity without external lookups; production deployments may
// substitute a resolver that joins to Okta or another canonical source.
type IdentityResolver func(ctx context.Context, channel, nativeID string) (Identity, error)

// PassthroughResolver is the zero-config IdentityResolver. It produces an
// Identity whose Canonical form is "<channel>:<nativeID>". Suitable for
// hackathon-grade deployments and tests.
func PassthroughResolver(_ context.Context, channel, nativeID string) (Identity, error) {
	return Identity{
		Canonical: channel + ":" + nativeID,
		Display:   nativeID,
		Sources:   map[string]string{channel: nativeID},
	}, nil
}

// ---------------------------------------------------------------------------
// Built-in routers
// ---------------------------------------------------------------------------

// SeverityRouter returns a Router that maps Messages to destinations based on
// Severity. Messages below minSeverity are dropped (no destinations returned).
// Each severity that has no explicit mapping falls back to defaultTarget on
// defaultChannel.
func SeverityRouter(defaultChannel, defaultTarget string, minSeverity Severity, bySeverity map[Severity]Destination) Router {
	return func(m Message) []Destination {
		if !m.Severity.AtLeast(minSeverity) {
			return nil
		}
		if d, ok := bySeverity[m.Severity]; ok {
			return []Destination{d}
		}
		return []Destination{{Channel: defaultChannel, Target: defaultTarget}}
	}
}

// FixedRouter routes every Message to a single destination regardless of
// content. Useful for tests and trivial deployments.
func FixedRouter(channel, target string) Router {
	return func(m Message) []Destination {
		return []Destination{{Channel: channel, Target: target}}
	}
}

// MultiRouter composes routers; results are concatenated in order. Useful for
// broadcasting (post to Slack AND email).
func MultiRouter(routers ...Router) Router {
	return func(m Message) []Destination {
		var out []Destination
		for _, r := range routers {
			out = append(out, r(m)...)
		}
		return out
	}
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

// Dispatcher owns a set of named Channels and a Router, and provides the three
// high-level operations workflows actually call. Activities in
// channels/temporal wrap these methods.
type Dispatcher struct {
	channels map[string]Channel
	router   Router
}

// Option configures a Dispatcher at construction time.
type Option func(*Dispatcher)

// WithChannel registers a Channel under its Name. Channels with empty Name
// are rejected at construction.
func WithChannel(c Channel) Option {
	return func(d *Dispatcher) {
		if c.Name == "" {
			return
		}
		d.channels[c.Name] = c
	}
}

// WithRouter sets the Dispatcher's Router. Required.
func WithRouter(r Router) Option {
	return func(d *Dispatcher) { d.router = r }
}

// New constructs a Dispatcher. The returned Dispatcher is safe for concurrent
// use by goroutines; the configuration is immutable after construction.
func New(opts ...Option) (*Dispatcher, error) {
	d := &Dispatcher{channels: map[string]Channel{}}
	for _, opt := range opts {
		opt(d)
	}
	if d.router == nil {
		return nil, fmt.Errorf("channels: dispatcher requires a Router")
	}
	if len(d.channels) == 0 {
		return nil, fmt.Errorf("channels: dispatcher requires at least one Channel")
	}
	for name, ch := range d.channels {
		if ch.Notify == nil {
			return nil, fmt.Errorf("channels: channel %q has nil Notify", name)
		}
	}
	return d, nil
}

// Send routes a Message and posts it to each destination's channel. The
// returned receipts are in destination order; failures from individual
// channels do not abort the send (they are reported alongside the receipts).
func (d *Dispatcher) Send(ctx context.Context, m Message) ([]Receipt, []error) {
	dests := d.router(m)
	if len(dests) == 0 {
		return nil, []error{ErrNoTarget}
	}
	var (
		receipts []Receipt
		errs     []error
	)
	for _, dest := range dests {
		ch, ok := d.channels[dest.Channel]
		if !ok {
			errs = append(errs, fmt.Errorf("channels: %w: %s", ErrUnknownChannel, dest.Channel))
			continue
		}
		// Per-destination copy so adapters don't see leaked Target from prior dests.
		mCopy := m
		mCopy.Target = dest.Target
		r, err := ch.Notify(ctx, mCopy)
		if err != nil {
			errs = append(errs, fmt.Errorf("channels: %s notify: %w", dest.Channel, err))
			continue
		}
		// Ensure Channel/Target are always populated on the receipt, even if
		// the adapter forgot.
		if r.Channel == "" {
			r.Channel = dest.Channel
		}
		if r.Target == "" {
			r.Target = dest.Target
		}
		if r.PostedAt.IsZero() {
			r.PostedAt = time.Now()
		}
		receipts = append(receipts, r)
	}
	return receipts, errs
}

// AwaitVerdict waits for the first valid Verdict across the receipts.
// Receipts whose channel does not implement Await are skipped silently;
// if none of the receipts have an Await-capable channel, returns
// ErrNoChannelSupportsAwait.
//
// Quorum > 1 is not yet implemented; this version returns on the first valid
// verdict (Quorum 0 or 1 semantics). Multi-vote quorum will require parallel
// polling across receipts, which is straightforward but deferred.
func (d *Dispatcher) AwaitVerdict(ctx context.Context, receipts []Receipt, opts AwaitOpts) (Verdict, error) {
	awaitable := 0
	for _, r := range receipts {
		ch, ok := d.channels[r.Channel]
		if !ok || ch.Await == nil {
			continue
		}
		awaitable++
		v, err := ch.Await(ctx, r, opts)
		if err == nil {
			if v.Channel == "" {
				v.Channel = r.Channel
			}
			return v, nil
		}
		// Continue trying other receipts on per-channel error.
	}
	if awaitable == 0 {
		return Verdict{}, ErrNoChannelSupportsAwait
	}
	return Verdict{}, ErrTimeout
}

// AwaitReplies harvests replies from all Converse-capable channels. Replies
// from each channel are concatenated in receipt order.
func (d *Dispatcher) AwaitReplies(ctx context.Context, receipts []Receipt, opts AwaitOpts) ([]Reply, error) {
	supportsConverse := 0
	var out []Reply
	for _, r := range receipts {
		ch, ok := d.channels[r.Channel]
		if !ok || ch.Converse == nil {
			continue
		}
		supportsConverse++
		replies, err := ch.Converse(ctx, r, opts)
		if err != nil {
			continue
		}
		out = append(out, replies...)
	}
	if supportsConverse == 0 {
		return nil, ErrNoChannelSupportsConverse
	}
	return out, nil
}

// ChannelNames returns the registered channel names in arbitrary order.
// Useful for diagnostics and tests.
func (d *Dispatcher) ChannelNames() []string {
	out := make([]string, 0, len(d.channels))
	for name := range d.channels {
		out = append(out, name)
	}
	return out
}
