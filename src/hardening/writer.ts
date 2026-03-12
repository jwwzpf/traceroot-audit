import { writeFile } from "node:fs/promises";
import path from "node:path";

import YAML from "yaml";

import type { HardeningPlan } from "./analysis";
import type { ManifestFormat } from "../manifest/template";

export interface HardeningWriteResult {
  reportPath: string;
  profilePath: string;
  manifestPath: string;
}

export async function writeHardeningFiles(
  plan: HardeningPlan,
  options: {
    manifestFormat: ManifestFormat;
  }
): Promise<HardeningWriteResult> {
  const reportPath = path.join(plan.rootDir, "traceroot.hardened.report.md");
  const profilePath = path.join(plan.rootDir, "traceroot.hardened.profile.json");
  const manifestPath = path.join(
    plan.rootDir,
    options.manifestFormat === "yaml"
      ? "traceroot.manifest.hardened.yaml"
      : "traceroot.manifest.hardened.json"
  );

  await writeFile(reportPath, renderHardeningMarkdown(plan), "utf8");
  await writeFile(profilePath, `${JSON.stringify(renderProfileJson(plan), null, 2)}\n`, "utf8");
  await writeFile(
    manifestPath,
    options.manifestFormat === "yaml"
      ? YAML.stringify(plan.recommendedManifest)
      : `${JSON.stringify(plan.recommendedManifest, null, 2)}\n`,
    "utf8"
  );

  return {
    reportPath,
    profilePath,
    manifestPath
  };
}

function renderProfileJson(plan: HardeningPlan) {
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    target: plan.target,
    targetPath: plan.targetPath,
    surface: plan.surfaceLabel,
    selectedIntents: plan.selectedProfiles.map((profile) => ({
      id: profile.id,
      title: profile.title
    })),
    selectedPolicies: {
      outboundApproval: plan.selections.outboundApproval,
      filesystemScope: plan.selections.filesystemScope,
      exposureMode: plan.selections.exposureMode
    },
    currentCapabilities: plan.currentCapabilities,
    recommendedCapabilities: plan.recommendedCapabilities,
    extraCapabilities: plan.extraCapabilities,
    missingCapabilities: plan.missingCapabilities,
    approvalPolicy: plan.approvalPolicy,
    fileWritePolicy: plan.fileWritePolicy,
    exposurePolicy: plan.exposurePolicy,
    immediateActions: plan.immediateActions,
    secretExposure: plan.secretExposure,
    findingsSummary: plan.findingsSummary,
    topFindings: plan.topFindings,
    recommendedManifest: plan.recommendedManifest
  };
}

function renderHardeningMarkdown(plan: HardeningPlan): string {
  const lines = [
    "# TraceRoot 收紧计划",
    "",
    `- **Target:** \`${plan.target}\``,
    `- **Surface:** \`${plan.surfaceLabel}\``,
    `- **你选中的工作流：** ${plan.selectedProfiles
      .map((profile) => `${profile.icon} ${profile.title}`)
      .join(", ")}`,
    `- **审批方式：** ${plan.approvalPolicy}`,
    `- **文件写入范围：** ${plan.fileWritePolicy}`,
    `- **网络暴露范围：** ${plan.exposurePolicy}`,
    "",
    "## 最值得先收紧的地方",
    ""
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
    "## 权限对比",
    "",
    `- **现在：** ${plan.currentCapabilities.length > 0 ? plan.currentCapabilities.join(", ") : "没有明显权限信号"}`,
    `- **建议最小范围：** ${plan.recommendedCapabilities.join(", ")}`,
    `- **还可以继续收掉的：** ${plan.extraCapabilities.length > 0 ? plan.extraCapabilities.join(", ") : "没有"}`,
    `- **这次工作流理论上还需要，但当前没看到的：** ${plan.missingCapabilities.length > 0 ? plan.missingCapabilities.join(", ") : "没有"}`,
    "",
    "## Secret 检查",
    ""
  );

  if (plan.secretExposure.length === 0) {
    lines.push("- 扫描到的文件里暂时没有发现环境变量 secrets。");
  } else {
    for (const exposure of plan.secretExposure) {
      lines.push(
        `- \`${exposure.variable}\` → ${exposure.group}（${exposure.action === "keep" ? "可以保留" : "建议 review 或移出"}）`
      );
    }
  }

  lines.push("", "## 当前最重要的风险", "");

  if (plan.topFindings.length === 0) {
    lines.push("- 当前没有明显风险。");
  } else {
    for (const finding of plan.topFindings) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.ruleId} ${finding.title}: ${finding.message}`);
    }
  }

  lines.push("", "## TraceRoot 建议的 manifest", "", "```json", JSON.stringify(plan.recommendedManifest, null, 2), "```", "");

  return `${lines.join("\n")}\n`;
}
