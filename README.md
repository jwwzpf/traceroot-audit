# TraceRoot Audit

[简体中文](./README.zh-CN.md)

[![npm version](https://img.shields.io/npm/v/traceroot-audit.svg)](https://www.npmjs.com/package/traceroot-audit)
[![CI](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwzpf/traceroot-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

**Runtime audit for local agents.**

TraceRoot Audit watches OpenClaw-, MCP-, and other local agent runtimes, alerts you when they attempt risky actions, and keeps a readable local audit trail you can review later.

![TraceRoot Audit demo GIF](./docs/assets/traceroot-demo.gif)

## Start

```bash
npx traceroot-audit@0.3.1 doctor --watch --host
npx traceroot-audit@0.3.1 logs --today
```

`doctor --watch --host` starts runtime watching.

`logs --today` shows what your agents did today and what deserves attention now.

## What You Get

- Live alerts when a local agent attempts risky actions
- A readable local audit trail instead of raw runtime logs
- Support for OpenClaw-, MCP-, and other local agent runtimes

## Most Common Commands

Watch your machine:

```bash
npx traceroot-audit@0.3.1 doctor --watch --host
```

Watch one runtime you already know:

```bash
npx traceroot-audit@0.3.1 doctor /path/to/openclaw --watch
```

Review today's audit trail:

```bash
npx traceroot-audit@0.3.1 logs --today
```

Run a local scan before launch:

```bash
npx traceroot-audit@0.3.1 scan .
```

## Language

CLI output defaults to English.

If you prefer Chinese:

```bash
npx traceroot-audit@0.3.1 doctor --watch --host --lang zh
```

or:

```bash
TRACEROOT_LANG=zh npx traceroot-audit@0.3.1 doctor --watch --host
```

## Local Development

```bash
pnpm install
pnpm build
```

If you do not use `pnpm`:

```bash
npm install
npm run build
```

## License

Apache-2.0
