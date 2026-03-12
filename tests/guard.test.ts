import { describe, expect, it } from "vitest";

import {
  createHostSnapshot,
  createScanSnapshot,
  diffHostSnapshots,
  diffScanSnapshots
} from "../src/core/guard";
import {
  diffBoundaryStatus,
  evaluateBoundaryStatus
} from "../src/hardening/boundary";

describe("guard snapshot diffs", () => {
  it("detects new and resolved findings in scan snapshots", () => {
    const previous = createScanSnapshot({
      target: ".",
      targetPath: "/tmp/example",
      surface: {
        kind: "project",
        confidence: "medium",
        reasons: ["test"]
      },
      riskScore: 5,
      summary: {
        critical: 1,
        high: 0,
        medium: 0,
        total: 1
      },
      findings: [
        {
          ruleId: "C001",
          severity: "critical",
          title: "Public Runtime Exposure",
          message: "runtime exposed",
          file: "docker-compose.yml",
          line: 2,
          evidence: "0.0.0.0",
          recommendation: "bind localhost"
        }
      ],
      manifestPath: null,
      baselinePath: null,
      suppressedCount: 0
    });

    const current = createScanSnapshot({
      target: ".",
      targetPath: "/tmp/example",
      surface: {
        kind: "project",
        confidence: "medium",
        reasons: ["test"]
      },
      riskScore: 2.5,
      summary: {
        critical: 0,
        high: 1,
        medium: 0,
        total: 1
      },
      findings: [
        {
          ruleId: "H001",
          severity: "high",
          title: "Missing Trust Metadata",
          message: "missing manifest",
          file: null,
          recommendation: "add manifest"
        }
      ],
      manifestPath: null,
      baselinePath: null,
      suppressedCount: 0
    });

    const diff = diffScanSnapshots(previous, current);

    expect(diff.changed).toBe(true);
    expect(diff.riskChanged).toBe(true);
    expect(diff.riskDelta).toBe(-2.5);
    expect(diff.newFindingCount).toBe(1);
    expect(diff.resolvedFindingCount).toBe(1);
  });

  it("detects new host surfaces and promotions", () => {
    const previous = createHostSnapshot({
      target: "host",
      homeDir: "/Users/example",
      cwd: "/Users/example/work",
      includeCwd: false,
      searchedRoots: ["~"],
      candidates: [
        {
          absolutePath: "/Users/example/tools/gmail",
          displayPath: "~/tools/gmail",
          surface: {
            kind: "skill",
            confidence: "medium",
            reasons: ["test"]
          },
          filesDiscovered: 2,
          manifestPath: null,
          strongSignals: ["gmail.mcp.json"],
          score: 18,
          tier: "possible",
          categoryLabel: "MCP / tool server",
          attention: "test",
          recommendedAction: "harden",
          recommendedActionLabel: "harden this MCP/tool surface before wiring it into an agent",
          recommendedCommand: "traceroot-audit harden '/Users/example/tools/gmail'"
        }
      ]
    });

    const current = createHostSnapshot({
      target: "host",
      homeDir: "/Users/example",
      cwd: "/Users/example/work",
      includeCwd: false,
      searchedRoots: ["~"],
      candidates: [
        {
          absolutePath: "/Users/example/tools/gmail",
          displayPath: "~/tools/gmail",
          surface: {
            kind: "skill",
            confidence: "high",
            reasons: ["test"]
          },
          filesDiscovered: 3,
          manifestPath: null,
          strongSignals: ["gmail.mcp.json"],
          score: 32,
          tier: "best-first",
          categoryLabel: "MCP / tool server",
          attention: "test",
          recommendedAction: "harden",
          recommendedActionLabel: "harden this MCP/tool surface before wiring it into an agent",
          recommendedCommand: "traceroot-audit harden '/Users/example/tools/gmail'"
        },
        {
          absolutePath: "/Users/example/.openclaw",
          displayPath: "~/.openclaw",
          surface: {
            kind: "runtime",
            confidence: "high",
            reasons: ["test"]
          },
          filesDiscovered: 4,
          manifestPath: null,
          strongSignals: ["docker-compose.yml"],
          score: 40,
          tier: "best-first",
          categoryLabel: "OpenClaw runtime",
          attention: "test",
          recommendedAction: "harden",
          recommendedActionLabel: "run the hardening wizard to shrink the runtime first",
          recommendedCommand: "traceroot-audit harden '/Users/example/.openclaw'"
        }
      ]
    });

    const diff = diffHostSnapshots(previous, current);

    expect(diff.changed).toBe(true);
    expect(diff.promotedToBestFirst).toHaveLength(1);
    expect(diff.promotedToBestFirst[0]?.displayPath).toBe("~/tools/gmail");
    expect(diff.newBestFirst).toHaveLength(1);
    expect(diff.newBestFirst[0]?.displayPath).toBe("~/.openclaw");
  });

  it("detects violations against an approved hardening boundary", () => {
    const status = evaluateBoundaryStatus(
      {
        target: ".",
        targetPath: "/tmp/example",
        surface: "runtime config",
        selectedIntents: [
          {
            id: "email-reply",
            title: "邮件整理与回复"
          }
        ],
        selectedPolicies: {
          outboundApproval: "always-confirm",
          filesystemScope: "workspace-only",
          exposureMode: "localhost-only"
        },
        currentCapabilities: ["email", "filesystem", "network", "shell"],
        recommendedCapabilities: ["email", "network"],
        extraCapabilities: ["filesystem", "shell"],
        missingCapabilities: [],
        approvalPolicy: "always confirm before sending or posting",
        fileWritePolicy: "workspace-only file writes",
        exposurePolicy: "localhost only; no network exposure",
        immediateActions: [],
        secretExposure: [],
        findingsSummary: {
          critical: 1,
          high: 0,
          medium: 0,
          total: 1
        },
        topFindings: [],
        recommendedManifest: {
          name: "example",
          version: "0.1.0",
          author: "tester",
          source: "https://example.com/runtime",
          capabilities: ["email", "network"],
          risk_level: "high",
          side_effects: true,
          confirmation_required: true,
          interrupt_support: "supported",
          idempotency: "unknown",
          safeguards: ["localhost_only_runtime"]
        }
      },
      {
        target: ".",
        targetPath: "/tmp/example",
        rootDir: "/tmp/example",
        manifest: {
          name: "example",
          version: "0.1.0",
          author: "tester",
          source: "https://example.com/runtime",
          capabilities: ["email", "network", "shell", "filesystem"],
          risk_level: "critical",
          side_effects: true,
          confirmation_required: false,
          interrupt_support: "supported",
          idempotency: "unknown"
        },
        manifestPath: "traceroot.manifest.json",
        currentCapabilities: ["email", "filesystem", "network", "shell"],
        secretExposure: [
          {
            variable: "AWS_SECRET_ACCESS_KEY",
            group: "cloud",
            action: "review"
          }
        ],
        findingsSummary: {
          critical: 1,
          high: 1,
          medium: 0,
          total: 2
        },
        topFindings: [],
        publicExposureDetected: true
      }
    );

    expect(status.aligned).toBe(false);
    expect(status.violations.map((violation) => violation.code)).toEqual([
      "unexpected-capabilities",
      "public-exposure",
      "missing-confirmation",
      "secret-exposure"
    ]);
  });

  it("detects new and resolved boundary violations", () => {
    const previous = {
      aligned: false,
      violations: [
        {
          code: "unexpected-capabilities",
          severity: "critical" as const,
          title: "More power than approved",
          message: "shell still enabled",
          recommendation: "disable shell",
          fingerprint: "unexpected-capabilities:shell"
        },
        {
          code: "secret-exposure",
          severity: "high" as const,
          title: "Unrelated secrets are still visible",
          message: "AWS secret visible",
          recommendation: "move secret out",
          fingerprint: "secret-exposure:AWS_SECRET_ACCESS_KEY"
        }
      ]
    };

    const current = {
      aligned: false,
      violations: [
        {
          code: "unexpected-capabilities",
          severity: "critical" as const,
          title: "More power than approved",
          message: "shell still enabled",
          recommendation: "disable shell",
          fingerprint: "unexpected-capabilities:shell"
        },
        {
          code: "public-exposure",
          severity: "critical" as const,
          title: "Public or network exposure is still possible",
          message: "runtime reachable",
          recommendation: "bind localhost",
          fingerprint: "public-exposure"
        }
      ]
    };

    const diff = diffBoundaryStatus(previous, current);

    expect(diff.changed).toBe(true);
    expect(diff.newViolations).toHaveLength(1);
    expect(diff.newViolations[0]?.code).toBe("public-exposure");
    expect(diff.resolvedViolations).toHaveLength(1);
    expect(diff.resolvedViolations[0]?.code).toBe("secret-exposure");
  });
});
