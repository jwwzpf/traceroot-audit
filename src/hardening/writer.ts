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
    target: plan.target,
    targetPath: plan.targetPath,
    surface: plan.surfaceLabel,
    selectedIntents: plan.selectedProfiles.map((profile) => ({
      id: profile.id,
      title: profile.title
    })),
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
    "# TraceRoot Audit Hardening Plan",
    "",
    `- **Target:** \`${plan.target}\``,
    `- **Surface:** \`${plan.surfaceLabel}\``,
    `- **Selected workflows:** ${plan.selectedProfiles
      .map((profile) => `${profile.icon} ${profile.title}`)
      .join(", ")}`,
    `- **Approval policy:** ${plan.approvalPolicy}`,
    `- **File write policy:** ${plan.fileWritePolicy}`,
    `- **Exposure policy:** ${plan.exposurePolicy}`,
    "",
    "## Immediate actions",
    ""
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
    "## Capability comparison",
    "",
    `- **Current:** ${plan.currentCapabilities.length > 0 ? plan.currentCapabilities.join(", ") : "none detected"}`,
    `- **Recommended:** ${plan.recommendedCapabilities.join(", ")}`,
    `- **Extra to remove or review:** ${plan.extraCapabilities.length > 0 ? plan.extraCapabilities.join(", ") : "none"}`,
    `- **Missing but expected for this workflow:** ${plan.missingCapabilities.length > 0 ? plan.missingCapabilities.join(", ") : "none"}`,
    "",
    "## Secret review",
    ""
  );

  if (plan.secretExposure.length === 0) {
    lines.push("- No environment secrets were detected in the scanned files.");
  } else {
    for (const exposure of plan.secretExposure) {
      lines.push(
        `- \`${exposure.variable}\` → ${exposure.group} (${exposure.action === "keep" ? "keep" : "review or move out"})`
      );
    }
  }

  lines.push("", "## Top findings", "");

  if (plan.topFindings.length === 0) {
    lines.push("- No existing findings were detected.");
  } else {
    for (const finding of plan.topFindings) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.ruleId} ${finding.title}: ${finding.message}`);
    }
  }

  lines.push("", "## Recommended manifest", "", "```json", JSON.stringify(plan.recommendedManifest, null, 2), "```", "");

  return `${lines.join("\n")}\n`;
}
