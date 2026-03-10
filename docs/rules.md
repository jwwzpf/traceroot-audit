# TraceRoot Audit Rules

TraceRoot Audit v0.1.0 ships with these built-in rules:

| ID | Severity | Title | What it detects |
| --- | --- | --- | --- |
| C001 | critical | Public Runtime Exposure | Public bind addresses such as `0.0.0.0` and obviously exposed local runtime ports in config or docker-compose files. |
| C002 | critical | Remote Fetch and Execute | `curl ... \| bash`, `wget ... \| sh`, and download-then-execute patterns in scripts. |
| C003 | critical | Untrusted Shell + Network + Filesystem Combo | Heuristic shell, network, and filesystem usage together when no trust manifest exists. |
| C004 | critical | Dangerous Destructive Capability Without Safeguards | Delete, remove, archive, purchase, email, or bulk-change behavior without confirmation or safeguard metadata. |
| H001 | high | Missing Trust Metadata | No valid `traceroot.manifest.json`, `.yaml`, or `.yml` file at the scan root. |
| H002 | high | Overbroad Permission Declaration | Too many high-risk capabilities declared at once in the manifest. |
| H004 | high | Hardcoded External Endpoints | External HTTP(S) endpoints embedded directly in scripts or config files. |
| H006 | high | No Replay / Idempotency Declaration | Side-effecting behavior without an `idempotency` declaration in trust metadata. |
| H007 | high | Missing Interrupt / Stop Contract Declaration | Destructive or long-running behavior without an `interrupt_support` declaration. |

## Minimal manifest schema

The v1 manifest schema is intentionally small:

```json
{
  "name": "order-food-skill",
  "version": "0.1.0",
  "author": "example-dev",
  "source": "https://github.com/example/order-food-skill",
  "capabilities": ["network", "browser"],
  "risk_level": "high",
  "side_effects": true,
  "idempotency": "unknown",
  "interrupt_support": "unknown"
}
```

Optional fields supported by the scanner include `confirmation_required` and `safeguards`.
