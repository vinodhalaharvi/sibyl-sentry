package main

import (
	"go.temporal.io/sdk/worker"

	"github.com/vinodhalaharvi/sibyl-sentry/jira"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/regex"
)

// Activity name strings live in their owning packages as ActivityName
// constants. The registration helpers below tie those names to the
// concrete function values for the worker.

func regexActivityOptions() worker.RegisterActivityOptions {
	return worker.RegisterActivityOptions{Name: regex.ActivityName}
}

func oauthActivityOptions() worker.RegisterActivityOptions {
	return worker.RegisterActivityOptions{Name: oauth.ActivityName}
}

func jiraActivityOptions() worker.RegisterActivityOptions {
	return worker.RegisterActivityOptions{Name: jira.ActivityName}
}
