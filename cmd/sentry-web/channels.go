package main

import (
	"time"

	"go.temporal.io/sdk/worker"

	"github.com/vinodhalaharvi/sibyl-sentry/channels"
	"github.com/vinodhalaharvi/sibyl-sentry/channels/slack"
	chtemporal "github.com/vinodhalaharvi/sibyl-sentry/channels/temporal"
)

// registerChannels constructs the dispatcher and registers the
// channels-related Temporal activities on the given worker.
//
// On success, the worker can serve the channels.Post / channels.AwaitVerdict /
// channels.AwaitReplies activities, and the audit workflow will fan-out to
// the configured channels when AuditInput.PostToChannels is true.
//
// On failure (bad token, missing scope, etc.), the worker is left untouched
// and the audit workflow continues to behave as if channels were disabled.
func registerChannels(w worker.Worker, slackToken, slackChannel string) error {
	slackCh, err := slack.New("slack",
		slack.NewSlackGoClient(slackToken),
		slack.Config{
			PollInterval: 5 * time.Second,
			VerdictByReaction: map[string]string{
				"white_check_mark": "accept",
				"x":                "reject",
				"zzz":              "snooze",
			},
		},
	)
	if err != nil {
		return err
	}

	dispatcher, err := channels.New(
		channels.WithChannel(slackCh),
		channels.WithRouter(channels.FixedRouter("slack", slackChannel)),
	)
	if err != nil {
		return err
	}

	acts, err := chtemporal.NewActivities(dispatcher)
	if err != nil {
		return err
	}
	acts.Register(w)
	return nil
}
