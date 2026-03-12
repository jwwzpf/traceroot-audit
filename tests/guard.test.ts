import { describe, expect, it } from "vitest";

import {
  createHostSnapshot,
  createScanSnapshot,
  diffHostSnapshots,
  diffScanSnapshots
} from "../src/core/guard";

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
});
