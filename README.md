# TraceRoot Audit

[简体中文](./README.zh-CN.md)

[![npm version](https://img.shields.io/npm/v/traceroot-audit.svg)](https://www.npmjs.com/package/traceroot-audit)
[![CI](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

**Open-source trust and security scanner for agent skills and local agent runtimes.**

TraceRoot Audit helps developers quickly detect risky agent skills, unsafe execution patterns, overbroad permissions, missing trust metadata, weak provenance signals, and insecure runtime exposure in OpenClaw-like local agent ecosystems.

![TraceRoot Audit demo GIF](./docs/assets/traceroot-demo.gif)

## Why it matters

Agent skills can now trigger real actions like:

- shell execution
- file access
- network calls
- email changes
- purchases or other side effects

TraceRoot Audit keeps the first release narrow: local scanning, simple trust metadata, and actionable findings.

## Local development

```bash
pnpm install
pnpm build
```

If you do not use `pnpm`, local development works with npm too:

```bash
npm install
npm run build
```

## Fastest local usage

Run without global install:

```bash
npx traceroot-audit scan .
```

Scan the current directory:

```bash
node dist/cli/index.js scan
```

Create a starter trust manifest:

```bash
node dist/cli/index.js init
```

Record current findings as a baseline:

```bash
node dist/cli/index.js baseline
```

## Quick start

Scan the current project:

```bash
node dist/cli/index.js scan .
```

Scan an OpenClaw-like local runtime repo:

```bash
node dist/cli/index.js scan /path/to/openclaw
```

Scan the bundled risky example:

```bash
node dist/cli/index.js scan ./examples/risky-skill
```

Output JSON for CI:

```bash
node dist/cli/index.js scan . --format json
```

Output Markdown for PRs or issues:

```bash
node dist/cli/index.js scan . --format markdown
```

Output compact Markdown for PR comments on mobile:

```bash
node dist/cli/index.js scan . --format markdown --compact
```

Fail CI on high-risk findings:

```bash
node dist/cli/index.js scan . --fail-on high
```

Ignore an existing baseline for one scan:

```bash
node dist/cli/index.js scan . --ignore-baseline
```

Use an explicit baseline file:

```bash
node dist/cli/index.js scan . --baseline ./traceroot.baseline.json
```

Generate SARIF for GitHub code scanning:

```bash
node dist/cli/index.js scan . --format sarif > traceroot.sarif
```

List built-in rules:

```bash
node dist/cli/index.js rules
```

Explain a rule:

```bash
node dist/cli/index.js explain C002
```

## Ignore generated or irrelevant paths

Add a `.tracerootignore` file at the scan root:

```text
# Ignore build output
dist/**
coverage/**

# Ignore vendored skills or generated scripts
vendor/**
generated/**
```

TraceRoot Audit will skip matching files during discovery.

## Baseline workflow

Baseline support is for gradual rollout in noisy repositories:

```bash
node dist/cli/index.js baseline .
node dist/cli/index.js scan .
```

The first command writes `traceroot.baseline.json`. After that, `scan` auto-detects the file and suppresses already accepted findings so that only new findings remain visible.

## GitHub Actions

Use the bundled composite action:

```yaml
name: TraceRoot Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/traceroot-audit@v1
        with:
          path: .
          fail-on: high
```

Replace `your-org` with the GitHub owner after you publish and tag `v1`.

If you prefer plain CLI in CI:

```yaml
- uses: actions/checkout@v4
- uses: pnpm/action-setup@v4
  with:
    version: 10.6.5
- uses: actions/setup-node@v4
  with:
    node-version: 20
- run: pnpm install --no-frozen-lockfile
- run: pnpm build
- run: node dist/cli/index.js scan . --fail-on high
```

Upload SARIF to GitHub code scanning:

```yaml
- uses: actions/checkout@v4
- uses: pnpm/action-setup@v4
  with:
    version: 10.6.5
- uses: actions/setup-node@v4
  with:
    node-version: 20
- run: pnpm install --no-frozen-lockfile
- run: pnpm build
- run: node dist/cli/index.js scan . --format sarif > traceroot.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: traceroot.sarif
```

PR comment summary job:

The repository CI now includes a PR summary job that runs:

```bash
node dist/cli/index.js scan . --format markdown --compact
```

and upserts the result as a PR comment instead of spamming a new comment on every push.
This repository also checks in a root `traceroot.baseline.json`, so the PR comment stays focused on newly introduced findings instead of known demo or fixture noise.
For forked pull requests, the workflow falls back to the GitHub Actions job summary because GitHub exposes a read-only token on `pull_request` events.

## Publish readiness

The package is set up for `npx traceroot-audit ...` and public npm publishing.

Useful checks before publishing:

```bash
npm run lint
npm test
npm run build
npm run package:check
```

## Automatic release

The repository now includes a tag-driven npm publish workflow in [.github/workflows/release.yml](./.github/workflows/release.yml).

To use it:

1. Configure npm trusted publishing for this package and repository.
2. Bump `package.json` version.
3. Push a tag like `v0.1.0`.

The workflow will lint, test, build, dry-run the package, publish to npm, and attach the generated tarball to the GitHub Release.

If you cannot use trusted publishing, a granular npm token is the fallback. In that case, add it as `NPM_TOKEN` in GitHub Actions secrets and adjust the publish step to use `NODE_AUTH_TOKEN`.

## Implemented rules

- `C001` Public Runtime Exposure
- `C002` Remote Fetch and Execute
- `C003` Untrusted Shell + Network + Filesystem Combo
- `C004` Dangerous Destructive Capability Without Safeguards
- `H001` Missing Trust Metadata
- `H002` Overbroad Permission Declaration
- `H004` Hardcoded External Endpoints
- `H006` No Replay / Idempotency Declaration
- `H007` Missing Interrupt / Stop Contract Declaration

See [docs/rules.md](./docs/rules.md) for rule details and the minimal manifest schema.

## First milestone

The v1 milestone is intentionally small:

1. `pnpm build`
2. `node dist/cli/index.js init`
3. `node dist/cli/index.js scan ./examples/risky-skill`
4. `node dist/cli/index.js scan ./examples/risky-skill --format json`
5. `node dist/cli/index.js scan ./examples/risky-skill --fail-on high`

## License

Apache-2.0
