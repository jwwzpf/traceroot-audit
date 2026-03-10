import pc from "picocolors";

import {
  createFindingFingerprint,
  type Finding,
  type ScanResult
} from "./findings";
import { builtInRules } from "../rules";
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
            semanticVersion: "0.1.0",
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
