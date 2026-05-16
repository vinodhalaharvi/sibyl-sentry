// Package temporal provides Temporal SDK bindings for the channels package.
// It registers Activities that delegate to a *channels.Dispatcher and exposes
// workflow-side helpers for invoking them. This package is the only place in
// the channels tree that imports go.temporal.io/sdk.
//
// The split keeps the core channels package dependency-free: code that needs
// raw channel dispatch (tests, CLI tools, non-Temporal callers) imports
// channels directly; code running inside Temporal imports channels/temporal.
package temporal

import (
	"context"
	"errors"
	"time"

	tsdkactivity "go.temporal.io/sdk/activity"
	tsdkworker "go.temporal.io/sdk/worker"
	tsdkworkflow "go.temporal.io/sdk/workflow"

	"github.com/vinodhalaharvi/sibyl-sentry/channels"
)

// Activities bundles the channel-related Temporal activities. Create an
// instance via NewActivities and register it on a worker.
type Activities struct {
	dispatcher *channels.Dispatcher
}

// NewActivities constructs an Activities value backed by the given Dispatcher.
func NewActivities(d *channels.Dispatcher) (*Activities, error) {
	if d == nil {
		return nil, errors.New("channels/temporal: dispatcher is required")
	}
	return &Activities{dispatcher: d}, nil
}

// Register registers all channels activities on the given worker with
// stable, well-known names. Workflows reference them by these names.
func (a *Activities) Register(w tsdkworker.Worker) {
	w.RegisterActivityWithOptions(a.Post, tsdkactivity.RegisterOptions{Name: ActivityPost})
	w.RegisterActivityWithOptions(a.AwaitVerdict, tsdkactivity.RegisterOptions{Name: ActivityAwaitVerdict})
	w.RegisterActivityWithOptions(a.AwaitReplies, tsdkactivity.RegisterOptions{Name: ActivityAwaitReplies})
}

// Activity names — exported so workflows can reference them by string when
// preferred over type-safe invocation.
const (
	ActivityPost         = "channels.Post"
	ActivityAwaitVerdict = "channels.AwaitVerdict"
	ActivityAwaitReplies = "channels.AwaitReplies"
)

// PostResult is the activity return type for Post. We don't return ([]Receipt,
// []error) directly because Temporal serializes a single error return; the
// per-channel errors are surfaced inside the result so workflow code can
// decide how to handle partial failures.
type PostResult struct {
	Receipts []channels.Receipt
	Errors   []string // per-destination error messages, in destination order
}

// Post is the Temporal activity entry point for Dispatcher.Send.
// Errors returned here represent activity-level failures (e.g. no
// destinations routed); per-destination failures live in PostResult.Errors.
func (a *Activities) Post(ctx context.Context, m channels.Message) (PostResult, error) {
	receipts, errs := a.dispatcher.Send(ctx, m)
	out := PostResult{Receipts: receipts}
	for _, e := range errs {
		out.Errors = append(out.Errors, e.Error())
	}
	if len(receipts) == 0 && len(errs) > 0 {
		// Surface the first error so Temporal records the activity as failed.
		return out, errs[0]
	}
	return out, nil
}

// AwaitVerdict is the Temporal activity entry point for
// Dispatcher.AwaitVerdict. It heartbeats while polling so that long-running
// awaits remain observable and can be cancelled.
func (a *Activities) AwaitVerdict(ctx context.Context, receipts []channels.Receipt, opts channels.AwaitOpts) (channels.Verdict, error) {
	// Spin a heartbeat alongside the dispatcher call so Temporal sees liveness.
	hbCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				tsdkactivity.RecordHeartbeat(ctx, "awaiting verdict")
			}
		}
	}()
	return a.dispatcher.AwaitVerdict(ctx, receipts, opts)
}

// AwaitReplies is the Temporal activity entry point for Dispatcher.AwaitReplies.
func (a *Activities) AwaitReplies(ctx context.Context, receipts []channels.Receipt, opts channels.AwaitOpts) ([]channels.Reply, error) {
	return a.dispatcher.AwaitReplies(ctx, receipts, opts)
}

// ---------------------------------------------------------------------------
// Workflow-side helpers
//
// These wrappers give workflows a typed, name-stable way to invoke the
// activities without hardcoding strings everywhere.
// ---------------------------------------------------------------------------

// PostOptions configures workflow-side activity invocation for Post.
type PostOptions struct {
	StartToCloseTimeout time.Duration
	HeartbeatTimeout    time.Duration
}

func (o PostOptions) toActivityOptions() tsdkworkflow.ActivityOptions {
	if o.StartToCloseTimeout <= 0 {
		o.StartToCloseTimeout = time.Minute
	}
	return tsdkworkflow.ActivityOptions{
		StartToCloseTimeout: o.StartToCloseTimeout,
		HeartbeatTimeout:    o.HeartbeatTimeout,
	}
}

// PostFromWorkflow invokes the Post activity from workflow code. Returns the
// receipts and any per-destination error strings.
func PostFromWorkflow(ctx tsdkworkflow.Context, m channels.Message, opts PostOptions) (PostResult, error) {
	ctx = tsdkworkflow.WithActivityOptions(ctx, opts.toActivityOptions())
	var result PostResult
	if err := tsdkworkflow.ExecuteActivity(ctx, ActivityPost, m).Get(ctx, &result); err != nil {
		return PostResult{}, err
	}
	return result, nil
}

// AwaitVerdictOptions configures workflow-side activity invocation for
// AwaitVerdict. StartToCloseTimeout MUST be longer than AwaitOpts.Timeout or
// the activity will be terminated before it can return ErrTimeout.
type AwaitVerdictOptions struct {
	StartToCloseTimeout time.Duration
	HeartbeatTimeout    time.Duration
}

func (o AwaitVerdictOptions) toActivityOptions() tsdkworkflow.ActivityOptions {
	if o.StartToCloseTimeout <= 0 {
		o.StartToCloseTimeout = time.Hour
	}
	if o.HeartbeatTimeout <= 0 {
		o.HeartbeatTimeout = 30 * time.Second
	}
	return tsdkworkflow.ActivityOptions{
		StartToCloseTimeout: o.StartToCloseTimeout,
		HeartbeatTimeout:    o.HeartbeatTimeout,
	}
}

// AwaitVerdictFromWorkflow invokes the AwaitVerdict activity from workflow
// code.
func AwaitVerdictFromWorkflow(
	ctx tsdkworkflow.Context,
	receipts []channels.Receipt,
	awaitOpts channels.AwaitOpts,
	wfOpts AwaitVerdictOptions,
) (channels.Verdict, error) {
	ctx = tsdkworkflow.WithActivityOptions(ctx, wfOpts.toActivityOptions())
	var v channels.Verdict
	if err := tsdkworkflow.ExecuteActivity(ctx, ActivityAwaitVerdict, receipts, awaitOpts).Get(ctx, &v); err != nil {
		return channels.Verdict{}, err
	}
	return v, nil
}

// AwaitRepliesFromWorkflow invokes the AwaitReplies activity from workflow
// code.
func AwaitRepliesFromWorkflow(
	ctx tsdkworkflow.Context,
	receipts []channels.Receipt,
	awaitOpts channels.AwaitOpts,
	wfOpts AwaitVerdictOptions,
) ([]channels.Reply, error) {
	ctx = tsdkworkflow.WithActivityOptions(ctx, wfOpts.toActivityOptions())
	var replies []channels.Reply
	if err := tsdkworkflow.ExecuteActivity(ctx, ActivityAwaitReplies, receipts, awaitOpts).Get(ctx, &replies); err != nil {
		return nil, err
	}
	return replies, nil
}
