import pc from "picocolors";

import type { DiscoveryResult, HostDiscoveryResult } from "./discovery";
import { hostScanCommandPath } from "./discovery";
import type { HardeningPlan } from "../hardening/analysis";
import {
  createFindingFingerprint,
  type Finding,
  type ScanResult
} from "./findings";
import { builtInRules } from "../rules";
import { surfaceLabel } from "./surfaces";
import { severityLabel, type FailOnSeverity } from "./severities";

function severityIcon(severity: Finding["severity"]): string {
  if (severity === "critical") {
    return "🛑";
  }

  if (severity === "high") {
    return "⚠️";
  }

  return "ℹ️";
}

function colorSeverity(severity: Finding["severity"], label: string): string {
  if (severity === "critical") {
    return pc.red(label);
  }

  if (severity === "high") {
    return pc.yellow(label);
  }

  return pc.cyan(label);
}

function formatFinding(finding: Finding): string[] {
  const header = `- ${severityIcon(finding.severity)} [${severityLabel(finding.severity)}] ${finding.ruleId} ${finding.title}`;
  const lines = [
    colorSeverity(finding.severity, header),
    `  📄 File: ${finding.file ?? "N/A"}`
  ];

  if (typeof finding.line === "number") {
    lines.push(`  📍 Line: ${finding.line}`);
  }

  if (finding.evidence) {
    lines.push(`  🧾 Evidence: ${finding.evidence}`);
  }

  lines.push(`  ℹ️  Message: ${finding.message}`);
  lines.push(`  🛠 Fix: ${finding.recommendation}`);

  return lines;
}

function pluralizeFindings(total: number): string {
  return total === 1 ? "finding" : "findings";
}

function escapeInlineCode(value: string): string {
  return value.replace(/`/g, "\\`");
}

function markdownField(label: string, value: string): string {
  return `- **${label}:** ${value}`;
}

function compactLocation(finding: Finding): string {
  if (!finding.file) {
    return "N/A";
  }

  return typeof finding.line === "number"
    ? `${finding.file}:${finding.line}`
    : finding.file;
}

function humanList(label: string, values: string[], limit = 4): string {
  if (values.length === 0) {
    return `${label}: none`;
  }

  const visibleValues = values.slice(0, limit);
  const suffix =
    values.length > visibleValues.length ? ` (+${values.length - visibleValues.length} more)` : "";

  return `${label}: ${visibleValues.join(", ")}${suffix}`;
}

function formatSurface(result: {
  surface: ScanResult["surface"] | DiscoveryResult["surface"] | HostDiscoveryResult["candidates"][number]["surface"];
}): string {
  return `${surfaceLabel(result.surface.kind)} (${result.surface.confidence} confidence)`;
}

export function renderHumanOutput(
  result: ScanResult,
  failOn: FailOnSeverity,
  failed: boolean
): string {
  const lines = [
    "TraceRoot Audit Report",
    "======================",
    "",
    `🎯 Target: ${result.target}`,
    `🧭 Scan surface: ${formatSurface(result)}`,
    `📊 Risk score: ${result.riskScore.toFixed(1)}/10`
  ];

  if (result.manifestPath) {
    lines.push(`📜 Manifest: ${result.manifestPath}`);
  }

  if (result.baselinePath) {
    lines.push(`🧷 Baseline: ${result.baselinePath}`);
  }

  if (result.baselineError) {
    lines.push(`⚠️ Baseline error: ${result.baselineError}`);
  }

  lines.push("", "🔎 Findings:");

  if (result.findings.length === 0) {
    lines.push("- ✅ No findings detected.");
  } else {
    for (const finding of result.findings) {
      lines.push(...formatFinding(finding), "");
    }

    if (lines[lines.length - 1] === "") {
      lines.pop();
    }
  }

  lines.push(
    "",
    "📈 Summary:",
    `${result.summary.total} ${pluralizeFindings(result.summary.total)} detected: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium`,
    result.suppressedCount > 0
      ? `🧹 Suppressed by baseline: ${result.suppressedCount}`
      : "🧹 Suppressed by baseline: 0",
    "",
    "🚦 Exit status:",
    failOn === "none"
      ? "✅ passed (`--fail-on none`)"
      : failed
        ? `❌ failed due to --fail-on ${failOn}`
        : `✅ passed (\`--fail-on ${failOn}\`)`
  );

  return `${lines.join("\n")}\n`;
}

export function renderJsonOutput(result: ScanResult): string {
  return `${JSON.stringify(
    {
      target: result.target,
      surface: {
        kind: result.surface.kind,
        label: surfaceLabel(result.surface.kind),
        confidence: result.surface.confidence,
        reasons: result.surface.reasons
      },
      riskScore: result.riskScore,
      baseline: {
        path: result.baselinePath,
        suppressedCount: result.suppressedCount,
        error: result.baselineError ?? null
      },
      summary: {
        critical: result.summary.critical,
        high: result.summary.high,
        medium: result.summary.medium
      },
      findings: result.findings
    },
    null,
    2
  )}\n`;
}

export function renderMarkdownOutput(
  result: ScanResult,
  failOn: FailOnSeverity,
  failed: boolean,
  options: {
    compact?: boolean;
  } = {}
): string {
  if (options.compact) {
    const lines = [
      "# TraceRoot Audit Report",
      "",
      markdownField("Target", `\`${escapeInlineCode(result.target)}\``),
      markdownField("Scan surface", `\`${escapeInlineCode(formatSurface(result))}\``),
      markdownField("Risk score", `\`${result.riskScore.toFixed(1)}/10\``)
    ];

    if (result.manifestPath) {
      lines.push(markdownField("Manifest", `\`${escapeInlineCode(result.manifestPath)}\``));
    }

    if (result.baselinePath) {
      lines.push(markdownField("Baseline", `\`${escapeInlineCode(result.baselinePath)}\``));
    }

    if (result.baselineError) {
      lines.push(markdownField("Baseline error", result.baselineError));
    }

    lines.push(
      markdownField(
        "Summary",
        `\`${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.suppressedCount} suppressed\``
      ),
      markdownField(
        "Exit status",
        failOn === "none"
          ? "passed (`--fail-on none`)"
          : failed
            ? `failed due to \`--fail-on ${failOn}\``
            : `passed (\`--fail-on ${failOn}\`)`
      ),
      ""
    );

    if (result.findings.length === 0) {
      lines.push("## Findings", "", "✅ No findings detected.", "");
      return `${lines.join("\n")}\n`;
    }

    const compactFindings = result.findings.slice(0, 6);
    lines.push(`## Findings (${result.findings.length})`, "");

    for (const finding of compactFindings) {
      lines.push(
        `- ${severityIcon(finding.severity)} \`${finding.ruleId}\` ${finding.title} · \`${escapeInlineCode(compactLocation(finding))}\``,
        `  ${finding.message}`
      );
    }

    if (result.findings.length > compactFindings.length) {
      lines.push(
        `- … ${result.findings.length - compactFindings.length} more ${pluralizeFindings(result.findings.length - compactFindings.length)}`
      );
    }

    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  const lines = [
    "# TraceRoot Audit Report",
    "",
    markdownField("Target", `\`${escapeInlineCode(result.target)}\``),
    markdownField("Scan surface", `\`${escapeInlineCode(formatSurface(result))}\``),
    markdownField("Risk score", `\`${result.riskScore.toFixed(1)}/10\``)
  ];

  if (result.manifestPath) {
    lines.push(markdownField("Manifest", `\`${escapeInlineCode(result.manifestPath)}\``));
  }

  if (result.baselinePath) {
    lines.push(markdownField("Baseline", `\`${escapeInlineCode(result.baselinePath)}\``));
  }

  if (result.baselineError) {
    lines.push(markdownField("Baseline error", result.baselineError));
  }

  lines.push(
    "",
    "## Summary",
    "",
    "| Severity | Count |",
    "| --- | ---: |",
    `| Critical | ${result.summary.critical} |`,
    `| High | ${result.summary.high} |`,
    `| Medium | ${result.summary.medium} |`,
    `| Suppressed by baseline | ${result.suppressedCount} |`,
    "",
    markdownField(
      "Exit status",
      failOn === "none"
        ? "passed (`--fail-on none`)"
        : failed
          ? `failed due to \`--fail-on ${failOn}\``
          : `passed (\`--fail-on ${failOn}\`)`
    ),
    ""
  );

  if (result.findings.length === 0) {
    lines.push("## Findings", "", "✅ No findings detected.", "");
    return `${lines.join("\n")}\n`;
  }

  lines.push(`## Findings (${result.findings.length})`, "");

  for (const finding of result.findings) {
    const summary = `${severityIcon(finding.severity)} ${finding.ruleId} ${finding.title}`;
    lines.push(`<details>`, `<summary>${summary}</summary>`, "");
    lines.push(markdownField("Severity", `\`${finding.severity}\``));
    lines.push(
      markdownField(
        "File",
        finding.file ? `\`${escapeInlineCode(finding.file)}\`` : "N/A"
      )
    );

    if (typeof finding.line === "number") {
      lines.push(markdownField("Line", `\`${finding.line}\``));
    }

    lines.push(markdownField("Message", finding.message));

    if (finding.evidence) {
      lines.push(markdownField("Evidence", `\`${escapeInlineCode(finding.evidence)}\``));
    }

    lines.push(markdownField("Fix", finding.recommendation), "", `</details>`, "");
  }

  return `${lines.join("\n")}\n`;
}

export function renderDiscoveryHumanOutput(result: DiscoveryResult): string {
  const lines = [
    "TraceRoot Audit Discovery",
    "=========================",
    "",
    `🎯 Target: ${result.target}`,
    `🧭 Detected surface: ${formatSurface(result)}`,
    `📦 Scannable files found: ${result.filesDiscovered}`
  ];

  if (result.manifestPath) {
    lines.push(`📜 Manifest: ${result.manifestPath}`);
  }

  if (result.manifestError) {
    lines.push(`⚠️ Manifest error: ${result.manifestError}`);
  }

  lines.push("", "🧠 Why this target looks like that:");

  for (const reason of result.surface.reasons) {
    lines.push(`- ${reason}`);
  }

  lines.push(
    "",
    "🔎 What TraceRoot Audit can inspect here:",
    `- ${humanList("Manifest files", result.manifestFiles)}`,
    `- ${humanList("Environment files", result.envFiles)}`,
    `- ${humanList("Runtime config files", result.runtimeConfigFiles)}`,
    `- ${humanList("Executable action files", result.scriptFiles)}`,
    "",
    "📌 Suggested scan targets:"
  );

  for (const suggestion of result.suggestedTargets) {
    lines.push(
      `- ${surfaceLabel(suggestion.kind)} → ${suggestion.displayPath}`,
      `  Why: ${suggestion.reason}`
    );
  }

  if (result.suggestedTargets.length > 0) {
    const suggestedCommands = [
      ...new Set(result.suggestedTargets.slice(0, 4).map((suggestion) => suggestion.displayPath))
    ];

    lines.push("", "🚀 Try next:");

    for (const displayPath of suggestedCommands.slice(0, 3)) {
      lines.push(`- traceroot-audit scan ${displayPath}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export function renderDiscoveryJsonOutput(result: DiscoveryResult): string {
  return `${JSON.stringify(
    {
      target: result.target,
      targetPath: result.targetPath,
      rootDir: result.rootDir,
      targetType: result.targetType,
      surface: {
        kind: result.surface.kind,
        label: surfaceLabel(result.surface.kind),
        confidence: result.surface.confidence,
        reasons: result.surface.reasons
      },
      manifestPath: result.manifestPath,
      manifestError: result.manifestError ?? null,
      filesDiscovered: result.filesDiscovered,
      manifestFiles: result.manifestFiles,
      envFiles: result.envFiles,
      runtimeConfigFiles: result.runtimeConfigFiles,
      scriptFiles: result.scriptFiles,
      suggestedTargets: result.suggestedTargets
    },
    null,
    2
  )}\n`;
}

export function renderHostDiscoveryHumanOutput(result: HostDiscoveryResult): string {
  const lines = [
    "TraceRoot Audit Host Discovery",
    "==============================",
    "",
    "🖥️ Scope: common agent/runtime locations on this machine",
    `🏠 Home: ${result.homeDir}`,
    result.includeCwd
      ? `📂 Current directory included: ${result.cwd}`
      : `🚫 Current directory excluded: ${result.cwd}`,
    `🔎 Roots searched: ${result.searchedRoots.length}`,
    `📌 Likely agent action surfaces found: ${result.candidates.length}`
  ];

  if (result.candidates.length === 0) {
    lines.push(
      "",
      "No obvious local agent surfaces were found in the common locations we checked.",
      "",
      "Try next:",
      "- traceroot-audit discover --host --include-cwd",
      "- traceroot-audit discover .",
      "- traceroot-audit discover /path/to/openclaw",
      "- traceroot-audit scan /path/to/skills"
    );

    return `${lines.join("\n")}\n`;
  }

  lines.push("");

  for (const [index, candidate] of result.candidates.entries()) {
    lines.push(
      `${index + 1}. ${formatSurface(candidate)}`,
      `   📍 Path: ${candidate.displayPath}`,
      `   📦 Scannable files: ${candidate.filesDiscovered}`,
      `   🧠 Why: ${candidate.surface.reasons[0] ?? "best-effort host discovery guess"}`
    );

    if (candidate.strongSignals.length > 0) {
      lines.push(`   🔎 Signals: ${candidate.strongSignals.join(", ")}`);
    }

    lines.push("");
  }

  lines.push("🚀 Try next:");

  for (const candidate of result.candidates.slice(0, 3)) {
    lines.push(`- ${hostScanCommandPath(candidate.absolutePath)}`);
  }

  return `${lines.join("\n")}\n`;
}

export function renderHostDiscoveryJsonOutput(result: HostDiscoveryResult): string {
  return `${JSON.stringify(
    {
      target: result.target,
      homeDir: result.homeDir,
      cwd: result.cwd,
      includeCwd: result.includeCwd,
      searchedRoots: result.searchedRoots,
      candidates: result.candidates.map((candidate) => ({
        absolutePath: candidate.absolutePath,
        displayPath: candidate.displayPath,
        surface: {
          kind: candidate.surface.kind,
          label: surfaceLabel(candidate.surface.kind),
          confidence: candidate.surface.confidence,
          reasons: candidate.surface.reasons
        },
        filesDiscovered: candidate.filesDiscovered,
        manifestPath: candidate.manifestPath,
        strongSignals: candidate.strongSignals
      }))
    },
    null,
    2
  )}\n`;
}

export function renderHardeningHumanOutput(plan: HardeningPlan): string {
  const lines = [
    "TraceRoot Audit Hardening",
    "=========================",
    "",
    `🎯 Target: ${plan.target}`,
    `🧭 Surface: ${plan.surfaceLabel}`,
    `🧩 Selected workflows: ${plan.selectedProfiles
      .map((profile) => `${profile.icon} ${profile.title}`)
      .join(", ")}`,
    "",
    "✨ What you asked TraceRoot to do:",
    `- Approval mode: ${plan.approvalPolicy}`,
    `- File policy: ${plan.fileWritePolicy}`,
    `- Exposure policy: ${plan.exposurePolicy}`,
    "",
    "🧯 Immediate hardening actions:"
  ];

  if (plan.immediateActions.length === 0) {
    lines.push("- No immediate reductions were suggested.");
  } else {
    for (const action of plan.immediateActions) {
      lines.push(`- ${action}`);
    }
  }

  lines.push(
    "",
    "⚡ Power comparison:",
    `- Current capabilities: ${plan.currentCapabilities.length > 0 ? plan.currentCapabilities.join(", ") : "none detected"}`,
    `- Recommended minimum: ${plan.recommendedCapabilities.join(", ")}`,
    `- Extra power to shrink: ${plan.extraCapabilities.length > 0 ? plan.extraCapabilities.join(", ") : "none"}`,
    `- Missing but expected for your selected workflows: ${plan.missingCapabilities.length > 0 ? plan.missingCapabilities.join(", ") : "none"}`,
    ""
  );

  if (plan.secretExposure.length > 0) {
    const keepSecrets = plan.secretExposure.filter((entry) => entry.action === "keep");
    const reviewSecrets = plan.secretExposure.filter((entry) => entry.action === "review");

    lines.push("🔐 Secret review:");
    lines.push(
      `- Keep in runtime: ${keepSecrets.length > 0 ? keepSecrets.map((entry) => entry.variable).join(", ") : "none detected"}`,
      `- Review or move out: ${reviewSecrets.length > 0 ? reviewSecrets.map((entry) => entry.variable).join(", ") : "none"}`
    );
    lines.push("");
  }

  lines.push(
    "🚨 Existing findings that still matter:",
    `- ${plan.findingsSummary.total} findings currently detected (${plan.findingsSummary.critical} critical, ${plan.findingsSummary.high} high, ${plan.findingsSummary.medium} medium)`
  );

  for (const finding of plan.topFindings) {
    lines.push(
      `- ${severityIcon(finding.severity)} ${finding.ruleId} ${finding.title}: ${finding.message}`
    );
  }

  lines.push("", "📄 Recommended manifest preview:", `${JSON.stringify(plan.recommendedManifest, null, 2)}`);

  return `${lines.join("\n")}\n`;
}

function sarifLevel(severity: Finding["severity"]): "error" | "warning" | "note" {
  if (severity === "critical") {
    return "error";
  }

  if (severity === "high") {
    return "warning";
  }

  return "note";
}

export function renderSarifOutput(result: ScanResult): string {
  const sarifRules = builtInRules.map((rule) => ({
    id: rule.id,
    name: rule.title,
    shortDescription: {
      text: rule.title
    },
    fullDescription: {
      text: rule.description
    },
    help: {
      text: `${rule.whyItMatters}\n\nHow to fix: ${rule.howToFix}`
    },
    defaultConfiguration: {
      level: sarifLevel(rule.severity)
    },
    properties: {
      severity: rule.severity,
      precision: "medium",
      tags: ["agent-security", "traceroot-audit"]
    }
  }));

  const ruleIndexById = new Map(
    builtInRules.map((rule, index) => [rule.id, index] as const)
  );

  const sarif = {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "TraceRoot Audit",
            informationUri: "https://github.com/jwwzpf/traceroot-audit",
            semanticVersion: "0.2.0",
            rules: sarifRules
          }
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          ruleIndex: ruleIndexById.get(finding.ruleId),
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.message} Fix: ${finding.recommendation}`
          },
          locations: finding.file
            ? [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: finding.file
                    },
                    region:
                      typeof finding.line === "number"
                        ? {
                            startLine: finding.line
                          }
                        : undefined
                  }
                }
              ]
            : undefined,
          partialFingerprints: {
            primaryLocationLineHash: createFindingFingerprint(finding)
          },
          properties: {
            severity: finding.severity,
            evidence: finding.evidence,
            recommendation: finding.recommendation
          }
        })),
        invocations: [
          {
            executionSuccessful: true
          }
        ]
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
