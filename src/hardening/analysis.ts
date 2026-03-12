import path from "node:path";

import { discoverTarget } from "../core/discovery";
import { scanTarget } from "../core/scanner";
import { loadManifest } from "../manifest/loader";
import type { TraceRootManifest } from "../manifest/schema";
import { buildManifestTemplate, type ManifestFormat } from "../manifest/template";
import type { ScannableFile } from "../rules/types";
import { discoverFiles, resolveTarget } from "../utils/files";
import {
  getHardeningProfileById,
  type HardeningIntentId,
  type HardeningIntentProfile,
  type SecretGroup,
  type SupportedCapability
} from "./profiles";

export type OutboundApprovalMode =
  | "always-confirm"
  | "confirm-high-risk"
  | "allow-autonomous";
export type FilesystemScope = "no-write" | "workspace-only" | "broad-write";
export type ExposureMode = "localhost-only" | "lan-access";

export interface HardeningSelections {
  intentIds: HardeningIntentId[];
  outboundApproval: OutboundApprovalMode;
  filesystemScope: FilesystemScope;
  exposureMode: ExposureMode;
}

export interface SecretExposure {
  variable: string;
  group: SecretGroup;
  action: "keep" | "review" | "remove";
}

export interface HardeningPlan {
  target: string;
  targetPath: string;
  rootDir: string;
  surfaceLabel: string;
  manifestPath: string | null;
  selections: HardeningSelections;
  selectedProfiles: HardeningIntentProfile[];
  currentCapabilities: SupportedCapability[];
  recommendedCapabilities: SupportedCapability[];
  extraCapabilities: SupportedCapability[];
  missingCapabilities: SupportedCapability[];
  recommendedManifest: TraceRootManifest;
  immediateActions: string[];
  secretExposure: SecretExposure[];
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    total: number;
  };
  topFindings: {
    ruleId: string;
    severity: "critical" | "high" | "medium";
    title: string;
    message: string;
  }[];
  fileWritePolicy: string;
  exposurePolicy: string;
  approvalPolicy: string;
}

export interface HardeningCurrentState {
  target: string;
  targetPath: string;
  rootDir: string;
  manifest: TraceRootManifest | null;
  manifestPath: string | null;
  currentCapabilities: SupportedCapability[];
  secretExposure: SecretExposure[];
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    total: number;
  };
  topFindings: {
    ruleId: string;
    severity: "critical" | "high" | "medium";
    title: string;
    message: string;
  }[];
  publicExposureDetected: boolean;
}

const capabilityDetectors: Record<SupportedCapability, RegExp[]> = {
  shell: [
    /\bchild_process\b/i,
    /\bexec(?:Sync)?\s*\(/,
    /\bspawn(?:Sync)?\s*\(/,
    /\bsubprocess\b/i,
    /\bos\.system\s*\(/,
    /(?:^|\s)(?:bash|sh|zsh)\b/,
    /\brm\s+-rf\b/
  ],
  network: [
    /\bfetch\s*\(/,
    /\baxios\b/i,
    /\brequests?\b/i,
    /\bhttpx\b/i,
    /\bcurl\b/i,
    /\bwget\b/i,
    /https?:\/\//
  ],
  filesystem: [
    /\bfs\./i,
    /\bwriteFile(?:Sync)?\s*\(/,
    /\breadFile(?:Sync)?\s*\(/,
    /\bunlink(?:Sync)?\s*\(/,
    /\bmkdir(?:Sync)?\s*\(/,
    /\bcopyFile(?:Sync)?\s*\(/,
    /\bpathlib\b/i,
    /\bos\.remove\s*\(/,
    /\bopen\s*\(/
  ],
  browser: [
    /\bplaywright\b/i,
    /\bpuppeteer\b/i,
    /\bselenium\b/i,
    /\bpage\.goto\b/i,
    /\bchromium\b/i,
    /\bbrowser\b/i
  ],
  email: [
    /\bnodemailer\b/i,
    /\bsmtp\b/i,
    /\bsendgrid\b/i,
    /\bmailgun\b/i,
    /\bresend\b/i,
    /\bgmail\b/i,
    /\bemail\b/i
  ],
  payments: [/\bstripe\b/i, /\bpaypal\b/i, /\bcheckout\b/i, /\bpayment\b/i]
};

const secretGroupMatchers: Array<{
  group: SecretGroup;
  pattern: RegExp;
}> = [
  { group: "email", pattern: /(SMTP|SENDGRID|MAILGUN|RESEND|GMAIL|EMAIL)/i },
  { group: "social", pattern: /(TWITTER|TIKTOK|INSTAGRAM|FACEBOOK|META|YOUTUBE|X_API)/i },
  { group: "payment", pattern: /(STRIPE|PAYPAL|SHOPIFY|CHECKOUT|PAYMENT)/i },
  { group: "finance", pattern: /(TRADING|BROKER|BINANCE|COINBASE|TRADINGVIEW|POLYGON|IEX)/i },
  { group: "messaging", pattern: /(SLACK|TELEGRAM|WHATSAPP|DISCORD|TWILIO)/i },
  { group: "cloud", pattern: /(AWS_|AZURE_|GCP_|GOOGLE_CLOUD|VERCEL|NETLIFY|FIREBASE|S3_|RDS_)/i },
  { group: "database", pattern: /(DATABASE_URL|DB_|POSTGRES|MYSQL|MONGO|REDIS)/i },
  { group: "browser", pattern: /(COOKIE|SESSION|BROWSER|PLAYWRIGHT|PUPPETEER)/i },
  { group: "ai", pattern: /(OPENAI|ANTHROPIC|GEMINI|MISTRAL|CLAUDE|MODEL|LLM)/i }
];

function inferCapabilities(files: ScannableFile[], manifest: TraceRootManifest | null): SupportedCapability[] {
  const detected = new Set<SupportedCapability>();

  for (const capability of manifest?.capabilities ?? []) {
    if (
      capability === "shell" ||
      capability === "network" ||
      capability === "filesystem" ||
      capability === "browser" ||
      capability === "email" ||
      capability === "payments"
    ) {
      detected.add(capability);
    }
  }

  for (const file of files) {
    for (const capability of Object.keys(capabilityDetectors) as SupportedCapability[]) {
      if (capabilityDetectors[capability].some((pattern) => pattern.test(file.content))) {
        detected.add(capability);
      }
    }
  }

  return [...detected].sort();
}

function detectSecretExposures(
  files: ScannableFile[],
  allowedGroups: Set<SecretGroup>
): SecretExposure[] {
  const exposures = new Map<string, SecretExposure>();

  for (const file of files) {
    if (!path.basename(file.relativePath).startsWith(".env")) {
      continue;
    }

    for (const line of file.content.split(/\r?\n/)) {
      const trimmedLine = line.trim();

      if (trimmedLine.length === 0 || trimmedLine.startsWith("#")) {
        continue;
      }

      const match = trimmedLine.match(/^([A-Z0-9_]+)\s*=/);
      if (!match) {
        continue;
      }

      const variable = match[1]!;
      const matcher = secretGroupMatchers.find((entry) => entry.pattern.test(variable));
      const group = matcher?.group ?? "general";
      const action: SecretExposure["action"] = allowedGroups.has(group) ? "keep" : "review";

      exposures.set(variable, {
        variable,
        group,
        action
      });
    }
  }

  return [...exposures.values()].sort((left, right) => left.variable.localeCompare(right.variable));
}

function allowedSecretGroupsForIntentIds(intentIds: HardeningIntentId[]): Set<SecretGroup> {
  return new Set<SecretGroup>(
    intentIds.flatMap((intentId) => getHardeningProfileById(intentId).allowedSecretGroups)
  );
}

function uniqueCapabilities(
  profiles: HardeningIntentProfile[]
): SupportedCapability[] {
  const capabilities = new Set<SupportedCapability>();

  for (const profile of profiles) {
    profile.requiredCapabilities.forEach((capability) => capabilities.add(capability));
  }

  return [...capabilities].sort();
}

function recommendationActions(
  extraCapabilities: SupportedCapability[],
  selections: HardeningSelections,
  secretExposure: SecretExposure[]
): string[] {
  const actions: string[] = [];

  if (extraCapabilities.length > 0) {
    actions.push(`把这些当前工作流其实用不到的能力先收掉：${extraCapabilities.join(", ")}`);
  }

  if (selections.exposureMode === "localhost-only") {
    actions.push("尽量把 runtime 只留在本机，不要再暴露给局域网或外部。");
  }

  if (selections.outboundApproval !== "allow-autonomous") {
    actions.push("发消息、发帖、下单这类外发动作，先要求人工确认。");
  }

  if (selections.filesystemScope === "workspace-only") {
    actions.push("把文件写入范围收回到当前工作目录，不要放大到整台机器。");
  }

  if (selections.filesystemScope === "no-write") {
    actions.push("当前这类工作流不需要写文件时，就把本地写入能力关掉。");
  }

  const reviewSecrets = secretExposure.filter((entry) => entry.action === "review");
  if (reviewSecrets.length > 0) {
    actions.push(`把这 ${reviewSecrets.length} 个和当前工作流无关的 secrets 挪出 runtime 环境变量。`);
  }

  return actions.slice(0, 5);
}

function approvalPolicyLabel(mode: OutboundApprovalMode): string {
  if (mode === "always-confirm") {
    return "所有外发动作都先确认";
  }

  if (mode === "confirm-high-risk") {
    return "只在高风险外发动作前确认";
  }

  return "允许自主执行外发动作";
}

function fileScopeLabel(scope: FilesystemScope): string {
  if (scope === "no-write") {
    return "不允许本地写文件";
  }

  if (scope === "workspace-only") {
    return "只允许写当前工作目录";
  }

  return "允许更宽的本地写入范围";
}

function exposureLabel(mode: ExposureMode): string {
  return mode === "localhost-only"
    ? "只留在本机，不暴露给网络"
    : "允许局域网访问";
}

function buildRecommendedManifest(
  baseManifest: TraceRootManifest,
  selections: HardeningSelections,
  selectedProfiles: HardeningIntentProfile[],
  recommendedCapabilities: SupportedCapability[]
): TraceRootManifest {
  return {
    ...baseManifest,
    capabilities: recommendedCapabilities,
    risk_level: selectedProfiles.some((profile) => profile.riskLevel === "critical")
      ? "critical"
      : selectedProfiles.some((profile) => profile.riskLevel === "high")
        ? "high"
        : "medium",
    side_effects: selectedProfiles.some((profile) => profile.sideEffects),
    confirmation_required: selections.outboundApproval !== "allow-autonomous",
    interrupt_support: "supported",
    idempotency: selectedProfiles.some((profile) => profile.sideEffects)
      ? "unknown"
      : "not_applicable",
    safeguards: [
      ...new Set([
        selections.exposureMode === "localhost-only"
          ? "localhost_only_runtime"
          : "private_network_review_required",
        selections.filesystemScope === "workspace-only"
          ? "workspace_write_only"
          : selections.filesystemScope === "no-write"
            ? "no_local_file_writes"
            : "broad_file_write_review_required",
        selections.outboundApproval === "always-confirm"
          ? "approval_required_for_all_side_effects"
          : selections.outboundApproval === "confirm-high-risk"
            ? "approval_required_for_high_risk_side_effects"
            : "autonomous_side_effects_explicitly_allowed",
        ...selectedProfiles.flatMap((profile) => profile.recommendedSafeguards)
      ])
    ],
    intents: selectedProfiles.map((profile) => profile.id)
  };
}

function surfaceLabelForHumans(kind: string): string {
  if (kind === "runtime") {
    return "runtime config";
  }

  if (kind === "skill") {
    return "skill / tool package";
  }

  return "agent project";
}

export async function buildHardeningPlan(
  targetInput: string,
  selections: HardeningSelections
): Promise<HardeningPlan> {
  const selectedProfiles = selections.intentIds.map((intentId) => getHardeningProfileById(intentId));
  const currentState = await buildCurrentHardeningState(targetInput, selections.intentIds);
  const discovery = await discoverTarget(targetInput);
  const currentCapabilities = currentState.currentCapabilities;
  const recommendedCapabilities = uniqueCapabilities(selectedProfiles);
  const extraCapabilities = currentCapabilities.filter(
    (capability) => !recommendedCapabilities.includes(capability)
  );
  const missingCapabilities = recommendedCapabilities.filter(
    (capability) => !currentCapabilities.includes(capability)
  );
  const secretExposure = currentState.secretExposure;
  const baseManifest =
    currentState.manifest ?? (await buildManifestTemplate(currentState.rootDir));
  const recommendedManifest = buildRecommendedManifest(
    baseManifest,
    selections,
    selectedProfiles,
    recommendedCapabilities
  );

  return {
    target: targetInput,
    targetPath: currentState.targetPath,
    rootDir: currentState.rootDir,
    surfaceLabel: surfaceLabelForHumans(discovery.surface.kind),
    manifestPath: currentState.manifestPath,
    selections,
    selectedProfiles,
    currentCapabilities,
    recommendedCapabilities,
    extraCapabilities,
    missingCapabilities,
    recommendedManifest,
    immediateActions: recommendationActions(extraCapabilities, selections, secretExposure),
    secretExposure,
    findingsSummary: currentState.findingsSummary,
    topFindings: currentState.topFindings,
    fileWritePolicy: fileScopeLabel(selections.filesystemScope),
    exposurePolicy: exposureLabel(selections.exposureMode),
    approvalPolicy: approvalPolicyLabel(selections.outboundApproval)
  };
}

export async function buildCurrentHardeningState(
  targetInput: string,
  intentIds: HardeningIntentId[]
): Promise<HardeningCurrentState> {
  const resolvedTarget = await resolveTarget(targetInput);
  const files = await discoverFiles(resolvedTarget);
  const manifestLoadResult = await loadManifest(resolvedTarget.rootDir);
  const scanResult = await scanTarget(targetInput, { useBaseline: false });
  const currentCapabilities = inferCapabilities(files, manifestLoadResult.manifest);
  const allowedSecretGroups = allowedSecretGroupsForIntentIds(intentIds);

  return {
    target: targetInput,
    targetPath: resolvedTarget.absolutePath,
    rootDir: resolvedTarget.rootDir,
    manifest: manifestLoadResult.manifest,
    manifestPath: manifestLoadResult.manifestPath,
    currentCapabilities,
    secretExposure: detectSecretExposures(files, allowedSecretGroups),
    findingsSummary: scanResult.summary,
    topFindings: scanResult.findings.slice(0, 3).map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      title: finding.title,
      message: finding.message
    })),
    publicExposureDetected: scanResult.findings.some((finding) => finding.ruleId === "C001")
  };
}

export function recommendedManifestFormat(manifestPath: string | null): ManifestFormat {
  if (manifestPath?.endsWith(".yaml") || manifestPath?.endsWith(".yml")) {
    return "yaml";
  }

  return "json";
}
