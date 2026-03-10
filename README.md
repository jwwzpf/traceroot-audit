# TraceRoot Audit

[简体中文](./README.zh-CN.md)

**Open-source trust and security scanner for agent skills and local agent runtimes.**

TraceRoot Audit helps developers quickly detect risky agent skills, unsafe execution patterns, overbroad permissions, missing trust metadata, and insecure runtime exposure in OpenClaw-like agent ecosystems.

## Why it matters

Agent skills can now trigger real actions like:

- shell execution
- file access
- network calls
- email changes
- purchases or other side effects

TraceRoot Audit helps surface obvious trust and security risks before they cause damage.

## Install

```bash
npm install -g traceroot-audit
```

## Quick start

Scan the current project:

```bash
traceroot-audit scan .
```

Scan a skill package:

```bash
traceroot-audit scan ./skills/my-skill
```

Output JSON for CI:

```bash
traceroot-audit scan . --format json
```

Fail CI on high-risk findings:

```bash
traceroot-audit scan . --fail-on high
```

## What it checks

Initial checks include:

- publicly exposed local runtimes
- remote fetch-and-execute patterns
- unsafe shell/network/filesystem combinations
- missing trust metadata
- overbroad permissions
- weak provenance signals
- risky defaults in local agent projects

## Status

Early-stage open-source project.  
The first release focuses on detection and risk surfacing.

## Roadmap

- CLI scanner
- rule engine
- JSON output
- CI integration
- trust metadata suggestions

## License

Apache-2.0
