# Runtime Audit v1

## Goal

TraceRoot Audit should evolve from a static scanner into a local **AI runtime audit companion**.

The product should not only answer:

- what risky skills or configs are installed

It should also answer:

- what the agent is doing right now
- which actions are risky enough to deserve attention
- whether the live runtime is drifting beyond the boundary the user approved
- what happened recently, in a form the user can review later

## Product thesis

Users do not feel strong value from another static checker alone.

They feel value when TraceRoot:

1. helps them approve a smaller boundary
2. stays with the runtime afterwards
3. raises attention when risky actions start happening
4. keeps a clear audit trail they can review locally

This means the product has two layers:

1. **Preflight**
   - static scan of skills, runtime configs, secrets, exposure, overbroad power
2. **Runtime audit**
   - live watch
   - risk alerts
   - local audit log
   - historical review

Static scan stays important, but runtime audit becomes the more emotionally valuable part.

## First shipped slice

The first local runtime-audit loop should stay deliberately small:

- `traceroot-audit doctor /path/to/runtime --watch`
- local JSONL event storage in `~/.traceroot/audit/events.jsonl`
- `traceroot-audit logs` for recent timeline review
- `traceroot-audit tap --action ... -- command ...` for wrapped high-risk actions

This first slice is valuable even before action-level adapters exist, because it already gives users:

- a persistent local audit trail
- visible drift alerts while the runtime is live
- a way to review what changed later from the terminal

The next practical extension should be thin wrapped-action adapters, not universal tracing. That keeps the product honest while still letting it record real side-effecting events.

## Core user story

The most important target user is:

- a solo developer or operator
- running OpenClaw-like local agents on a laptop, desktop, or Mac mini
- giving the agent real side-effecting power
- wanting visibility, not full policy enforcement

Desired experience:

1. User runs `traceroot-audit doctor /path/to/runtime`
2. TraceRoot helps define what the agent is actually allowed to do
3. User runs `traceroot-audit doctor /path/to/runtime --watch`
4. TraceRoot stays alive beside the runtime
5. When risky actions happen, TraceRoot prints a visible alert immediately
6. Every action is written to a local audit log with severity and evidence
7. User can later review the timeline from the terminal

## v1 product surface

### Main commands

#### `doctor`

Current role:

- discover a likely surface
- ask what the user wants the AI to do
- approve a smaller boundary
- generate a safer bundle

New v1 role:

- remain the main entry point
- become the recommended way to enter runtime watch mode

Examples:

```bash
traceroot-audit doctor
traceroot-audit doctor /path/to/openclaw
traceroot-audit doctor /path/to/openclaw --watch
traceroot-audit doctor /path/to/openclaw --watch --interval 60
```

#### `scan`

Remains the preflight/static analysis tool.

Used for:

- installed skills
- runtime config
- MCP servers
- scripts and automation repos

#### `logs`

New command for local audit review.

Examples:

```bash
traceroot-audit logs
traceroot-audit logs --tail
traceroot-audit logs --severity high
traceroot-audit logs --today
traceroot-audit logs --target /path/to/openclaw
```

### Advanced command

#### `guard`

Keep as a lower-level advanced entry point.

Product guidance:

- ordinary users should not need to learn it
- `doctor --watch` is the default recommendation

## What runtime audit should monitor in v1

v1 should monitor **high-signal events only**.

We do not need full observability on day one.

We need enough to produce useful alerts and a credible local audit trail.

### Event families

#### 1. Boundary drift

Already close to existing functionality.

Examples:

- runtime becomes network-reachable again
- unexpected capabilities appear again
- confirmation guard is missing again
- unrelated secrets are still present or become present again

This is the lowest-risk, most reliable v1 event family.

#### 2. High-risk action attempts

Examples:

- destructive file delete or broad file modification
- outbound email send
- public post / social publish
- checkout / purchase / payment-like action
- access to sensitive env or credentials
- runtime touching finance or banking-related data sources

This is the most attention-grabbing user value in runtime audit.

#### 3. Sensitive access signals

Examples:

- reading `.env`
- touching payment or cloud secrets
- reading browser session/cookie stores
- reaching finance or payment connectors

This is not always “bad”, but it should be recorded and risk-labeled.

#### 4. Runtime lifecycle changes

Examples:

- runtime started watching
- runtime stopped
- new likely AI action surface appeared
- existing surface disappeared

These are lower severity but useful for the audit trail.

## Severity model

Runtime events should be easier to understand than rule IDs.

### Levels

- `safe`
- `risky`
- `high-risk`
- `critical`

### Meaning

#### `safe`

Examples:

- read-only analysis
- no new drift
- boundary still aligned

#### `risky`

Examples:

- external API access
- browser automation
- message drafting
- reading non-critical secrets

#### `high-risk`

Examples:

- outbound email send
- public post
- destructive file operation
- broad file write
- unrelated secret still exposed

#### `critical`

Examples:

- payment or purchase action
- banking or broker credential access
- destructive shell execution
- public exposure plus unexpected execution power

## v1 event sources

This is the most important implementation constraint.

TraceRoot cannot claim to know what every agent is doing unless it has a real signal source.

So v1 should support only event sources we can defend technically.

### Source A: file/config drift watch

Use existing scan + hardening boundary logic.

What it gives us:

- boundary drift
- exposure drift
- capability drift
- secret drift

This is the strongest v1 foundation and already partly exists.

### Source B: wrapped local action execution

Add a wrapper path for skills, scripts, and tool commands.

Concept:

```bash
traceroot-audit tap --event send-email --risk high -- command ...
```

or:

```bash
traceroot-audit exec --profile email-reply -- command ...
```

What this gives us:

- a reliable action event before/after a side-effecting command
- local evidence without pretending to see inside every agent runtime

This is the most realistic way to audit runtime actions in v1 for local skills and scripts.

### Source C: local log tail / structured event ingest

Support a configured log file or JSONL source from a runtime/tool server.

Examples:

- runtime writes JSON events to a file
- local hook appends events into a JSONL file

What this gives us:

- compatibility with runtimes that can emit logs but cannot be deeply integrated yet

### Out of scope for v1

- full OS-wide syscall tracing
- universal agent introspection
- blocking or stopping actions
- claiming perfect visibility into every runtime

## Local audit log

The audit log is a core product asset.

### Storage

Recommended default:

```text
~/.traceroot/audit/events.jsonl
```

Optional future per-target index:

```text
~/.traceroot/audit/targets/<hash>.jsonl
```

### Why JSONL

- append-only
- easy to tail
- easy to filter
- easy to summarize later

### Event schema

```json
{
  "timestamp": "2026-03-12T16:45:00Z",
  "runtime": "openclaw",
  "target": "/Users/example/.openclaw",
  "surface_kind": "runtime",
  "severity": "high-risk",
  "category": "outbound-action",
  "action": "send-email",
  "status": "attempted",
  "message": "Agent attempted an outbound email action without a clear approval guard.",
  "evidence": {
    "source": "wrapped-command",
    "tool": "gmail-send",
    "confirmation_required": false
  },
  "recommendation": "Require confirmation for outbound email actions in the active runtime profile."
}
```

### Required fields

- `timestamp`
- `severity`
- `category`
- `message`
- `source`
- `target`

### Optional fields

- `runtime`
- `surface_kind`
- `action`
- `status`
- `evidence`
- `recommendation`

## Alert channels

The product should start with the channels that keep onboarding simple.

### v1 channels

#### 1. terminal

Required.

Why:

- zero extra setup
- immediate feedback
- fits local runtime workflows

#### 2. local audit log

Required.

Why:

- creates reviewability
- creates trust
- allows later summaries

### v1.1 channel

#### webhook

Optional, generic, low-coupling extension.

Why:

- easier than building every chat app first
- lets advanced users bridge into Slack/Telegram/other tools themselves

### Not first in v1

- WhatsApp
- Telegram
- Slack-native notifier
- email notifier

Reason:

- extra auth and setup friction
- hurts the “simple, wow, local-first” onboarding

The system should be designed so these can be added later as notifier adapters.

## CLI output design

Runtime audit output should feel like an incident timeline, not static lint.

### Watch mode

Examples:

```text
🛑 High-risk AI action detected
Runtime: OpenClaw
Target: ~/.openclaw
Action: outbound email send
Why: no approval guard detected
Recorded: ~/.traceroot/audit/events.jsonl
```

```text
⚠️ Risky AI access recorded
Runtime: OpenClaw
Action: payment-related secret became visible
```

### Logs view

Examples:

```text
🛑 2026-03-12 16:45 send-email
Agent attempted an outbound email action without a clear approval guard.

⚠️ 2026-03-12 16:48 secret-exposure
AWS_SECRET_ACCESS_KEY remained visible to the runtime.

🟢 2026-03-12 16:55 boundary-aligned
No drift detected. Approved boundary still holds.
```

## v1 success criteria

v1 is successful if a user can say:

1. “I can see what my local agent is doing while it runs.”
2. “I get warned when it starts something I should care about.”
3. “I can go back later and review what happened.”
4. “I did not need to set up a whole security platform to get value.”

## What makes this feel like a product

The “wow” will not come from more rule IDs.

It will come from this feeling:

- my agent is alive
- TraceRoot is alive too
- TraceRoot is quietly watching beside it
- if something risky starts, I know right away
- if I want the history, it is already there

That is the product direction this spec supports.

## Recommended implementation order

### Step 1

Strengthen `doctor --watch` as the main runtime entry.

### Step 2

Add local audit event writing for:

- boundary drift
- exposure drift
- secret drift

### Step 3

Add `logs` for local review:

- default recent timeline
- `--tail`
- `--severity`
- `--today`
- `--target`

### Step 4

Add wrapped action events for local scripts/tools:

- side-effecting command execution
- outbound action attempts
- destructive file operations

### Step 5

Add generic webhook notifier / event sink as the first external extension point.

## Explicit non-goals for v1

- blocking agent actions
- killing processes automatically
- acting as a full enterprise SIEM
- claiming complete visibility into every local app
- requiring a cloud backend

v1 should stay:

- local-first
- transparent
- fast to install
- easy to understand
- useful on day one
