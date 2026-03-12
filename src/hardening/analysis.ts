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

function uniqueCapabilities(
  profiles: HardeningIntentProfile[],
  selections: HardeningSelections
): SupportedCapability[] {
  const capabilities = new Set<SupportedCapability>();

  for (const profile of profiles) {
    profile.requiredCapabilities.forEach((capability) => capabilities.add(capability));
  }

  if (selections.filesystemScope !== "no-write") {
    for (const profile of profiles) {
      profile.optionalCapabilities
        .filter((capability) => capability === "filesystem")
        .forEach((capability) => capabilities.add(capability));
    }
  }

  if (selections.outboundApproval !== "allow-autonomous") {
    for (const profile of profiles) {
      profile.optionalCapabilities
        .filter((capability) => capability === "email")
        .forEach((capability) => capabilities.add(capability));
    }
  }

  for (const profile of profiles) {
    profile.optionalCapabilities
      .filter((capability) => capability !== "filesystem" && capability !== "email")
      .forEach((capability) => capabilities.add(capability));
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
    actions.push(`remove or disable unnecessary capabilities: ${extraCapabilities.join(", ")}`);
  }

  if (selections.exposureMode === "localhost-only") {
    actions.push("bind the runtime to localhost only and avoid LAN/public exposure");
  }

  if (selections.outboundApproval !== "allow-autonomous") {
    actions.push("require explicit approval before outbound side-effecting actions");
  }

  if (selections.filesystemScope === "workspace-only") {
    actions.push("restrict filesystem writes to the intended workspace only");
  }

  if (selections.filesystemScope === "no-write") {
    actions.push("disable local filesystem write access for this workflow");
  }

  const reviewSecrets = secretExposure.filter((entry) => entry.action === "review");
  if (reviewSecrets.length > 0) {
    actions.push(`move ${reviewSecrets.length} unrelated secrets out of the runtime env`);
  }

  return actions.slice(0, 5);
}

function approvalPolicyLabel(mode: OutboundApprovalMode): string {
  if (mode === "always-confirm") {
    return "always confirm before sending or posting";
  }

  if (mode === "confirm-high-risk") {
    return "confirm high-risk outbound actions";
  }

  return "allow autonomous outbound actions";
}

function fileScopeLabel(scope: FilesystemScope): string {
  if (scope === "no-write") {
    return "no local file writes";
  }

  if (scope === "workspace-only") {
    return "workspace-only file writes";
  }

  return "broad file writes allowed";
}

function exposureLabel(mode: ExposureMode): string {
  return mode === "localhost-only"
    ? "localhost only; no network exposure"
    : "LAN access allowed";
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
  const resolvedTarget = await resolveTarget(targetInput);
  const files = await discoverFiles(resolvedTarget);
  const manifestLoadResult = await loadManifest(resolvedTarget.rootDir);
  const discovery = await discoverTarget(targetInput);
  const scanResult = await scanTarget(targetInput, { useBaseline: false });
  const selectedProfiles = selections.intentIds.map((intentId) => getHardeningProfileById(intentId));
  const currentCapabilities = inferCapabilities(files, manifestLoadResult.manifest);
  const recommendedCapabilities = uniqueCapabilities(selectedProfiles, selections);
  const extraCapabilities = currentCapabilities.filter(
    (capability) => !recommendedCapabilities.includes(capability)
  );
  const missingCapabilities = recommendedCapabilities.filter(
    (capability) => !currentCapabilities.includes(capability)
  );
  const allowedSecretGroups = new Set<SecretGroup>(
    selectedProfiles.flatMap((profile) => profile.allowedSecretGroups)
  );
  const secretExposure = detectSecretExposures(files, allowedSecretGroups);
  const baseManifest =
    manifestLoadResult.manifest ?? (await buildManifestTemplate(resolvedTarget.rootDir));
  const recommendedManifest = buildRecommendedManifest(
    baseManifest,
    selections,
    selectedProfiles,
    recommendedCapabilities
  );

  return {
    target: targetInput,
    targetPath: resolvedTarget.absolutePath,
    rootDir: resolvedTarget.rootDir,
    surfaceLabel: surfaceLabelForHumans(discovery.surface.kind),
    manifestPath: manifestLoadResult.manifestPath,
    selectedProfiles,
    currentCapabilities,
    recommendedCapabilities,
    extraCapabilities,
    missingCapabilities,
    recommendedManifest,
    immediateActions: recommendationActions(extraCapabilities, selections, secretExposure),
    secretExposure,
    findingsSummary: scanResult.summary,
    topFindings: scanResult.findings.slice(0, 3).map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      title: finding.title,
      message: finding.message
    })),
    fileWritePolicy: fileScopeLabel(selections.filesystemScope),
    exposurePolicy: exposureLabel(selections.exposureMode),
    approvalPolicy: approvalPolicyLabel(selections.outboundApproval)
  };
}

export function recommendedManifestFormat(manifestPath: string | null): ManifestFormat {
  if (manifestPath?.endsWith(".yaml") || manifestPath?.endsWith(".yml")) {
    return "yaml";
  }

  return "json";
}
