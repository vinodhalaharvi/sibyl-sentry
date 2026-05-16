# Sibyl Sentry

A **multi-agent** agentic security audit tool **built on durable Temporal workflows**.
Built for the Okta Hackapalooza ("Agentic Internal Tools" category).

Given an identity or environment, Sentry's `SecurityAuditWorkflow` fans out
parallel scanners — secret exposure, stale OAuth grants, over-privileged
scopes, dormant service accounts — and hands every candidate to a
**Researcher / Critic** agent pair. The Researcher proposes a finding;
the Critic demands cited evidence. Up to three rounds until they converge
or the candidate is rejected. Every conversation is a durable Temporal
workflow — replayable, resumable, fully auditable months later.

---

## Hackathon judges — start here

Sibyl Sentry is **two repositories**:

| Repo | What it is |
|------|------------|
| **sibyl-sentry** *(this repo)* | The application — scanners, multi-agent loop, web UI |
| **[sibyl-sentry-fixtures](https://github.com/vinodhalaharvi/sibyl-sentry-fixtures)** | The simulated environment — mock Okta/AWS/GitHub servers + planted findings |

Both are public. This README walks you through running the whole system locally.

**Demo flow:** start the mock vendor servers (fixtures repo) → start Temporal →
start Sentry → open the UI → click *Run Audit*. Watch four scanners fan out,
candidates converge through two adversarial Claude agents, and accepted
findings appear with the Critic's full reasoning.

---

## Prerequisites

- **Go 1.24+** — Sentry uses recent Go features. Check: `go version`
- **Temporal CLI** — for the local dev server.
  Install: `brew install temporal` (macOS) or [docs.temporal.io/cli](https://docs.temporal.io/cli)
- **Git, curl, make** — standard developer tooling
- *(Optional)* **Anthropic API key** *or* **Claude Code CLI** — for the agent
  loop. Without one, run with `-llm scripted` (canned responses, plumbing
  verification only)

Tested on macOS (Sonoma+) and Linux. Should work in WSL2.

---

## Full setup — four terminals

Total time: ~3 minutes start to finish.

### Terminal 1 — clone both repos

```sh
mkdir -p ~/go-projects && cd ~/go-projects
git clone https://github.com/vinodhalaharvi/sibyl-sentry.git
git clone https://github.com/vinodhalaharvi/sibyl-sentry-fixtures.git
```

Sentry expects the fixtures repo as a sibling directory; this layout matches
all default config paths.

### Terminal 2 — start the mock vendor servers

```sh
cd ~/go-projects/sibyl-sentry-fixtures
make mocks-up    # compiles + starts mock-okta, mock-aws, mock-github
make check       # verifies all three are healthy
make logs        # tails the access log — leave running
```

You'll see three mock servers listening:

```
mock-okta    http://localhost:9001   (Authorization: SSWS ...)
mock-aws     http://localhost:9002   (Authorization: AWS4-HMAC-SHA256 ...)
mock-github  http://localhost:9003   (Authorization: Bearer ...)
```

This terminal becomes your **live HTTP trace** — every time Sentry hits a
mock endpoint, you'll see the request show up here. Part of the demo.

### Terminal 3 — start Temporal

```sh
temporal server start-dev
```

Local Temporal server on `localhost:7233`, Web UI on `http://localhost:8233`.
Keep this running.

### Terminal 4 — start Sentry

```sh
cd ~/go-projects/sibyl-sentry

# First time only
go mod tidy
go build ./...

# Run the web server (in-process worker)
go run ./cmd/sentry-web -llm claude-code
```

Useful flags:

| Flag | Default | Effect |
|------|---------|--------|
| `-llm` | `scripted` | LLM backend: `scripted` \| `anthropic` \| `claude-code` |
| `-model` | (backend default) | LLM model name override |
| `-temporal` | `localhost:7233` | Temporal address |
| `-addr` | `:8090` | HTTP listen address for the UI |
| `-default-target` | `../sibyl-sentry-fixtures` | Repo to scan for secrets |
| `-max-candidates` | `5` | Cap candidates per scanner (bounds LLM fan-out) |

For the demo, use `-llm claude-code` (requires Claude Code CLI installed +
authenticated) or `-llm anthropic` (requires `ANTHROPIC_API_KEY` in env).

### Open the UI

```
http://localhost:8090
```

Click **Run Audit**. After ~10–15 seconds the synthesized brief appears with
accepted findings + Critic rationales.

Switch to the **DAG** tab to see the live topology: parent workflow → four
scanner activities → per-candidate child workflows → accept/reject verdicts.
Click any node to jump straight to its Temporal trace at `http://localhost:8233`.

---

## Architecture

```
SecurityAuditWorkflow                      ← durable parent workflow
├── 4 scanner activities (parallel)
│     ├── secrets        (regex + git history walk)
│     ├── stale-oauth    (mock-okta /api/v1/apps)
│     ├── over-priv      (mock-okta /apps/{id} + /logs)
│     └── dormancy       (mock-aws /iam/users + /access-keys)
│
├── per candidate:
│     ConvergeWorkflow                     ← durable child workflow (one per finding)
│       ├── ResearcherActivity             ← LLM agent: proposes finding + evidence
│       └── CriticActivity                 ← LLM agent: demands citations, accepts or rejects
│       (loops up to 3 rounds)
│
└── after synthesis:
      └── JiraTicketActivity              ← per accepted finding above threshold
```

**Why durable?** If a worker crashes mid-audit, Temporal resumes from the
exact step. If the LLM rate-limits, the workflow waits and retries. If one
scanner times out, the rest keep going. Every reasoning step from every
agent is replayable months later — perfect for compliance auditing.

**Why multi-agent?** A single LLM call would hallucinate findings. Forcing
a Researcher to convince an independent Critic, with concrete file/commit/
API-field citations or no finding, gives you scanner output that earns its
place in the queue.

---

## Build

Sentry depends on Sibyl (the agent runtime) as a regular Go module:

```sh
go mod tidy
go build ./...
```

### Build tags

| Tag | Effect |
|-----|--------|
| _(none)_ | Default. Pure-regex secret scanner. No CGO required. Fast tests. |
| `yara` | Enables the libyara-backed scanner. Requires `libyara` 4.3+ and `pkg-config`. |
| `sibyl_stub` | Builds against an in-tree Sibyl stub. Scaffold validation only — not for production. |

Examples:
```sh
go build ./...                          # default
go build -tags yara ./...               # YARA scanner enabled
```

### Makefile shortcuts

```sh
make build      # go build ./...
make test       # full test suite (fixture-dependent tests skip if fixtures absent)
make worker     # run the standalone worker (Temporal must be up)
make audit      # submit one audit via CLI
```

---

## Project layout

```
sibyl-sentry/
├── scanners/                  scanner activities (each is a Researcher)
│   ├── yara/                  YARA-based secret scanner (build tag: yara)
│   ├── regex/                 pure-Go regex secret scanner (default)
│   ├── oauth/                 stale OAuth grant scanner
│   ├── scopes/                over-privilege scanner
│   ├── reuse/                 token-reuse-across-contexts scanner
│   └── dormancy/              dormant service account scanner
├── okta/, aws/, github/       HTTP clients for the three vendor APIs
├── findings/                  shared Finding type + severity + evidence
├── owners/                    finding → Jira project/assignee resolution
├── jira/                      Jira client + ticket activity
├── audit/                     SecurityAuditWorkflow + checklist decomposer
├── prompts/                   Researcher + Critic prompt templates
├── rules/                     embedded YARA rules + regex patterns
├── web/                       SSE UI for the demo
├── internal/sibylproxy/       Sibyl interface (real or stub)
└── cmd/
    ├── sentry-worker/         runnable worker (standalone)
    ├── sentry-audit/          CLI: submit an audit, print the brief
    └── sentry-web/            HTTP server + SSE UI (worker in-process)
```

---

## Troubleshooting

**`go build` fails on imports:**
Run `go mod tidy` first. Make sure `go version` reports 1.24 or newer.

**Sentry can't reach the mocks:**
Confirm the mocks are running with `make check` in the fixtures repo. If
they're on non-default ports, pass `-okta-url`, `-aws-url`, `-github-url`
to `sentry-web`.

**"owners load: file not found":**
The default owners.json path is `../sibyl-sentry-fixtures/sentry-config/owners.json`
relative to where you run `sentry-web` from. Pass `-owners /abs/path/to/owners.json`
if your layout differs.

**Temporal Web UI shows no workflows:**
Confirm Temporal dev server is running (Terminal 3). Default address is
`localhost:7233`; override with `-temporal`.

**`-llm claude-code` errors:**
Claude Code CLI must be installed and authenticated on the host. Fall back
to `-llm anthropic` (with `ANTHROPIC_API_KEY` env) or `-llm scripted` (no
LLM call, plumbing verification only).

**Findings always rejected with scripted LLM:**
Expected. `-llm scripted` returns canned responses; use a real LLM backend
to see the Critic actually reasoning over evidence.

---

## Implemented vs simulated

**~75% real / 25% mocked.**

*Real, runs end-to-end:* All scanner code, all Temporal workflows, the
multi-agent Researcher/Critic loop, the React UI with List + DAG views,
SSE streaming, Jira ticket creation, owner resolution.

*Mocked:* The Okta, AWS, and GitHub API calls hit the
[sibyl-sentry-fixtures](https://github.com/vinodhalaharvi/sibyl-sentry-fixtures)
mock servers instead of live tenants. The mocks serve the same JSON shapes
the real APIs return. Production path is one base-URL config change per
vendor — no code changes to the scanners themselves.

---

## Related

- **[sibyl-sentry-fixtures](https://github.com/vinodhalaharvi/sibyl-sentry-fixtures)** — mock vendor APIs + planted findings (run this first)
- **[sibyl](https://github.com/vinodhalaharvi/sibyl)** — underlying multi-agent runtime (Temporal + Go)

---

*Built for Okta Hackapalooza, FY27 — "Agentic Internal Tools". Author: Vinod Halaharvi. Reporting to Les Zychowski. Privacy Engineering and Security Engineering.*
