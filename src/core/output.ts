import pc from "picocolors";

import {
  hostCandidateAttentionForHuman,
  hostCandidateCategoryForHuman,
  hostCandidateRecommendedStepForHuman,
  type DiscoveryResult,
  type HostDiscoveryResult
} from "./discovery";
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

function confidenceForHuman(confidence: "high" | "medium" | "low"): string {
  if (confidence === "high") {
    return "把握较高";
  }

  if (confidence === "medium") {
    return "有一定把握";
  }

  return "先当作线索";
}

function surfaceReasonForHuman(reason: string): string {
  switch (reason) {
    case "found TraceRoot manifest metadata":
    case "contains TraceRoot manifest metadata":
      return "这里已经有 TraceRoot manifest，说明它更像一个可复用的动作包。";
    case 'target path looks like a "skill", "tool", or "plugin" package':
      return "路径本身就很像一个 skill / tool 包。";
    case "contains executable files that define reusable agent actions":
      return "这里有可执行文件，而且更像在定义可复用的 agent 动作。";
    case "found environment files that can shape a local runtime":
      return "这里有环境变量文件，通常会直接影响本地运行态的能力边界。";
    case "found docker-compose runtime exposure or wiring files":
      return "这里有 docker-compose 一类的运行态接线或暴露配置。";
    case "found config files that likely define runtime behavior":
      return "这里有配置文件，看起来会直接影响运行态行为。";
    case 'target path looks like a "runtime" or "config" surface':
      return "路径本身就很像运行态或配置入口。";
    case "contains helper scripts under a runtime/config path":
      return "这里还有运行态相关的辅助脚本。";
    case "contains executable files that can become agent actions":
      return "这里有可执行文件，后面很可能会被 agent 当成动作来调用。";
    case "contains multiple action-capable source files":
      return "这里不止一个动作入口，更值得先留意。";
    case "mixes executable code with runtime/config wiring":
      return "这里把可执行代码和运行态配置混在了一起，更像真实入口。";
    case "single file target looks like a runnable automation script":
      return "这个单文件目标本身就很像可以直接跑起来的自动化脚本。";
    case "contains runtime wiring or environment files":
      return "这里有运行态接线或环境变量文件。";
    case 'directory name suggests a "skill" or "tool" package':
      return "目录名本身就很像一个 skill / tool 包。";
    case "directory name suggests a runtime/config surface":
      return "目录名本身就很像运行态或配置入口。";
    case "found only a small amount of scanable material, so this is a best-effort guess":
      return "目前线索不多，TraceRoot 先按最像入口的位置帮你猜了一次。";
    default:
      return reason;
  }
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
    lines.push(`- ${surfaceReasonForHuman(reason)}`);
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
      `  Why: ${surfaceReasonForHuman(suggestion.reason)}`
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
  const bestFirstCandidates = result.candidates.filter(
    (candidate) => candidate.tier === "best-first"
  );
  const possibleCandidates = result.candidates.filter(
    (candidate) => candidate.tier === "possible"
  );
  const lines = [
    "TraceRoot Audit Host Discovery",
    "==============================",
    "",
    "🖥️ Scope: 这台机器上常见的 agent / runtime 位置",
    `🏠 Home: ${result.homeDir}`,
    result.includeCwd
      ? `📂 当前目录也算进来了：${result.cwd}`
      : `🚫 当前目录先不算进来：${result.cwd}`,
    `🔎 已检查的位置：${result.searchedRoots.length}`,
    `📌 当前找到的可疑入口：${result.candidates.length}`
  ];

  if (result.candidates.length === 0) {
    lines.push(
      "",
      "暂时还没在这些常见位置里看到明显的 agent / runtime 入口。",
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

  if (bestFirstCandidates.length > 0) {
    lines.push(
      "🎯 Best first checks:",
      "这些地方最像 OpenClaw、MCP、skill 或 runtime 入口，建议先从这里看。",
      ""
    );
  } else {
    lines.push(
      "🧭 Possible surfaces:",
      "这里还没看到特别强的 OpenClaw 线索，所以先把最像入口的位置列出来。",
      ""
    );
  }

  const primaryList =
    bestFirstCandidates.length > 0 ? bestFirstCandidates : result.candidates.slice(0, 5);

  for (const [index, candidate] of primaryList.entries()) {
    lines.push(
      `${index + 1}. ${hostCandidateCategoryForHuman(candidate)}（${confidenceForHuman(candidate.surface.confidence)}）`,
      `   📍 Path: ${candidate.displayPath}`,
      `   📦 能先看见的文件：${candidate.filesDiscovered}`,
      `   🧠 TraceRoot 为什么会注意到这里：${surfaceReasonForHuman(candidate.surface.reasons[0] ?? "found only a small amount of scanable material, so this is a best-effort guess")}`,
      `   ✨ 为什么值得先看：${hostCandidateAttentionForHuman(candidate)}`,
      `   ➡️ 建议先做：${hostCandidateRecommendedStepForHuman(candidate)}`,
      `   🛠 Command: ${candidate.recommendedCommand}`
    );

    if (candidate.strongSignals.length > 0) {
      lines.push(`   🔎 Signals: ${candidate.strongSignals.join(", ")}`);
    }

    lines.push("");
  }

  if (bestFirstCandidates.length > 0 && possibleCandidates.length > 0) {
    lines.push(
      "🧪 Other possible surfaces:",
      "这些地方也值得留意，但没有上面那批入口那么像真正的 agent / runtime 位置。",
      ""
    );

    for (const [index, candidate] of possibleCandidates.slice(0, 3).entries()) {
      lines.push(
        `${index + 1}. ${hostCandidateCategoryForHuman(candidate)}（${confidenceForHuman(candidate.surface.confidence)}）`,
        `   📍 Path: ${candidate.displayPath}`,
        `   ✨ 为什么值得留意：${hostCandidateAttentionForHuman(candidate)}`,
        `   ➡️ 建议先做：${hostCandidateRecommendedStepForHuman(candidate)}`
      );

      if (candidate.strongSignals.length > 0) {
        lines.push(`   🔎 Signals: ${candidate.strongSignals.join(", ")}`);
      }

      lines.push("");
    }
  }

  lines.push("🚀 Try next:");

  for (const candidate of primaryList.slice(0, 3)) {
    lines.push(`- ${candidate.recommendedCommand}`);
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
        strongSignals: candidate.strongSignals,
        score: candidate.score,
        tier: candidate.tier,
        categoryLabel: candidate.categoryLabel,
        attention: candidate.attention,
        recommendedAction: candidate.recommendedAction,
        recommendedActionLabel: candidate.recommendedActionLabel,
        recommendedCommand: candidate.recommendedCommand
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
    `🧩 你选中的工作流：${plan.selectedProfiles
      .map((profile) => `${profile.icon} ${profile.title}`)
      .join(", ")}`,
    "",
    "✨ 你刚才让 TraceRoot 帮你守住的是：",
    `- 审批方式：${plan.approvalPolicy}`,
    `- 文件写入范围：${plan.fileWritePolicy}`,
    `- 网络暴露范围：${plan.exposurePolicy}`,
    "",
    "🧯 最值得先收紧的地方："
  ];

  if (plan.immediateActions.length === 0) {
    lines.push("- 暂时没有明显需要立刻收紧的地方。");
  } else {
    for (const action of plan.immediateActions) {
      lines.push(`- ${action}`);
    }
  }

  lines.push(
    "",
    "⚡ 权限对比：",
    `- 现在：${plan.currentCapabilities.length > 0 ? plan.currentCapabilities.join(", ") : "没有明显权限信号"}`,
    `- 建议最小范围：${plan.recommendedCapabilities.join(", ")}`,
    `- 还可以继续收掉的：${plan.extraCapabilities.length > 0 ? plan.extraCapabilities.join(", ") : "没有"}`,
    `- 这次工作流理论上还需要，但当前没看到的：${plan.missingCapabilities.length > 0 ? plan.missingCapabilities.join(", ") : "没有"}`,
    ""
  );

  if (plan.secretExposure.length > 0) {
    const keepSecrets = plan.secretExposure.filter((entry) => entry.action === "keep");
    const reviewSecrets = plan.secretExposure.filter((entry) => entry.action === "review");

    lines.push("🔐 Secret 检查：");
    lines.push(
      `- 可以留在 runtime 里的：${keepSecrets.length > 0 ? keepSecrets.map((entry) => entry.variable).join(", ") : "没有明显需要保留的"}`,
      `- 建议 review 或移出的：${reviewSecrets.length > 0 ? reviewSecrets.map((entry) => entry.variable).join(", ") : "没有"}`
    );
    lines.push("");
  }

  lines.push(
    "🚨 当前仍然需要你注意的风险：",
    `- 目前一共发现 ${plan.findingsSummary.total} 条（critical ${plan.findingsSummary.critical} / high ${plan.findingsSummary.high} / medium ${plan.findingsSummary.medium}）`
  );

  for (const finding of plan.topFindings) {
    lines.push(
      `- ${severityIcon(finding.severity)} ${finding.ruleId} ${finding.title}: ${finding.message}`
    );
  }

  lines.push("", "📄 TraceRoot 建议的 manifest 预览：", `${JSON.stringify(plan.recommendedManifest, null, 2)}`);

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
