# TraceRoot Audit

TraceRoot Audit is an open-source trust and security scanner for agent skills and local agent runtimes.

It helps developers detect risky agent skills, unsafe execution patterns, overbroad permissions, missing trust metadata, and weak provenance in OpenClaw-like agent ecosystems.

## Goals

- Detect suspicious or dangerous skill behavior
- Flag unsafe runtime and deployment configurations
- Surface missing trust metadata and provenance signals
- Make agent ecosystems easier to inspect, trust, and secure

## Initial scope

- Scan skill packages and local agent projects
- Detect dangerous shell/network execution patterns
- Flag missing metadata and trust declarations
- Report overbroad permissions and risky defaults
- Produce human-readable and machine-readable audit reports
