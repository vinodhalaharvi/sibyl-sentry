# Sibyl Sentry

An agentic security-posture tool built on [Sibyl](https://github.com/vinodhalaharvi/sibyl).

Given an identity or system, Sentry's `SecurityAuditWorkflow` fans out parallel
investigations — secret exposure (YARA), stale OAuth grants, over-privileged
scopes, token reuse across contexts, dormant service accounts — and synthesizes
a prioritized brief. Findings above a severity threshold are filed as Jira
tickets routed to the right owner.

**Project status:** hackathon MVP — scaffold + YARA scanner + Jira agent.
Fixture target: [sibyl-sentry-fixtures](https://github.com/vinodhalaharvi/sibyl-sentry-fixtures).

## Architecture

```
SecurityAuditWorkflow (Sentry)            ← decomposes by checklist, not heuristic
├── ConvergeWorkflow (Sibyl)              ← per sub-investigation
│     ├── ResearcherActivity (Sentry)     ← per scanner type (YARA, OAuth, ...)
│     └── CriticActivity (Sibyl)          ← evidence-or-reject loop
└── after synthesis:
      └── JiraTicketActivity (Sentry)     ← per finding above threshold
```

Sibyl is the runtime (Temporal workflows, Researcher/Critic convergence loop,
LLM seam). Sentry is the application (specific scanners, Jira agent, owners
map, web UI).

## Build

Sentry depends on Sibyl as a regular Go module:

```sh
go mod tidy        # fetches github.com/vinodhalaharvi/sibyl
go build ./...
```

### Build tags

| Tag | Effect |
|-----|--------|
| _(none)_ | Default. Uses pure-regex secret scanner. No CGO required. Fast tests. |
| `yara` | Enables the libyara-backed scanner. Requires `libyara` 4.3+ and `pkg-config` installed on the build host. |
| `sibyl_stub` | Builds against an in-tree stub of Sibyl's public API (`internal/sibylproxy`). Used only for scaffold validation when the real Sibyl module isn't available. **Not for production.** |

Examples:

```sh
go build ./...                       # regex scanner, real Sibyl
go build -tags yara ./...            # YARA scanner, real Sibyl
go build -tags sibyl_stub ./...      # regex scanner, stub Sibyl (dev only)
go build -tags "yara sibyl_stub" ./... # YARA scanner, stub Sibyl
```

## Quick start

Terminal 1 — Temporal dev server:

```sh
temporal server start-dev
```

Terminal 2 — Sentry worker:

```sh
go run ./cmd/sentry-worker -fixtures-path ../sibyl-sentry-fixtures
```

Terminal 3 — submit an audit:

```sh
go run ./cmd/sentry-audit -target ../sibyl-sentry-fixtures
```

The worker registers Sibyl's workflows + Sentry's scanner activities. The audit
CLI submits a `SecurityAuditWorkflow` and prints the synthesized brief. Watch
the parallel child workflows in the Temporal Web UI at http://localhost:8233.

## Project layout

```
sibyl-sentry/
├── scanners/                  scanner activities (each is a Researcher)
│   ├── yara/                  YARA-based secret scanner (build tag: yara)
│   ├── regex/                 pure-Go regex secret scanner (default fallback)
│   ├── oauth/                 stale OAuth grant scanner
│   ├── scopes/                over-privilege scanner
│   ├── reuse/                 token-reuse-across-contexts scanner
│   └── dormancy/              dormant service account scanner
├── findings/                  shared Finding type + severity + evidence
├── owners/                    finding → Jira project/assignee resolution
├── jira/                      Jira client + ticket activity
├── audit/                     SecurityAuditWorkflow + checklist decomposer
├── rules/                     embedded YARA rules + regex patterns
├── web/                       SSE UI for the demo (cmd/sentry-web)
├── internal/sibylproxy/       stub Sibyl interface (build tag: sibyl_stub)
└── cmd/
    ├── sentry-worker/         runnable worker
    ├── sentry-audit/          CLI: submit an audit and print the brief
    └── sentry-web/            HTTP server + SSE UI
```

## License

Internal hackathon project.
