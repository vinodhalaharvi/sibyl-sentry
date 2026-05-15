package main

import (
	"go.temporal.io/sdk/activity"

	"github.com/vinodhalaharvi/sibyl-sentry/jira"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/dormancy"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/oauth"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/regex"
	"github.com/vinodhalaharvi/sibyl-sentry/scanners/scopes"
)

// Activity name strings live in their owning packages as ActivityName
// constants. The registration helpers below tie those names to the
// concrete function values for the worker.

func regexActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: regex.ActivityName}
}

func oauthActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: oauth.ActivityName}
}

func scopesActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: scopes.ActivityName}
}

func dormancyActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: dormancy.ActivityName}
}

func jiraActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: jira.ActivityName}
}
