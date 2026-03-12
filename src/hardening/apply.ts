import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import fg from "fast-glob";
import YAML from "yaml";

import { recommendedManifestFormat } from "./analysis";
import type { SavedHardeningProfile } from "./profile";
import type { SecretExposure } from "./analysis";
import { discoverFiles, resolveTarget } from "../utils/files";
import type { ScannableFile } from "../rules/types";
import type { AuditSeverity } from "../audit/types";

const composePatterns = ["docker-compose.yml", "docker-compose.yaml"];

export interface ApplyBundleResult {
  rootDir: string;
  planPath: string;
  manifestPath: string;
  envExamplePath: string | null;
  composeOverridePath: string | null;
  composeSourcePath: string | null;
  keptSecrets: string[];
  movedSecrets: string[];
  tapWrapperDir: string | null;
  tapPlanPath: string | null;
  tapWrappers: TapWrapperFile[];
}

export interface TapWrapperFile {
  action: string;
  severity: AuditSeverity;
  wrapperPath: string;
  sourcePath: string;
  recommendation: string;
}

function manifestOutputPath(rootDir: string, manifestFormat: "json" | "yaml"): string {
  return path.join(
    rootDir,
    manifestFormat === "yaml"
      ? "traceroot.manifest.hardened.yaml"
      : "traceroot.manifest.hardened.json"
  );
}

async function findComposeFile(rootDir: string): Promise<string | null> {
  const [composeFile] = await fg(composePatterns, {
    cwd: rootDir,
    onlyFiles: true,
    dot: true
  });

  return composeFile ? path.join(rootDir, composeFile) : null;
}

function rewritePortString(port: string): string | null {
  const trimmed = port.trim();
  const match = trimmed.match(
    /^(?:(?<ip>\d+\.\d+\.\d+\.\d+):)?(?<host>\d+):(?<container>\d+)(?<suffix>\/(?:tcp|udp))?$/
  );

  if (!match?.groups) {
    return null;
  }

  const host = match.groups.host;
  const container = match.groups.container;
  const suffix = match.groups.suffix ?? "";

  return `127.0.0.1:${host}:${container}${suffix}`;
}

function buildComposeOverride(rawCompose: string): string | null {
  const parsed = YAML.parse(rawCompose);

  if (!parsed || typeof parsed !== "object" || typeof parsed.services !== "object") {
    return null;
  }

  const overrideServices: Record<string, Record<string, unknown>> = {};

  for (const [serviceName, serviceValue] of Object.entries(
    parsed.services as Record<string, unknown>
  )) {
    if (!serviceValue || typeof serviceValue !== "object") {
      continue;
    }

    const service = serviceValue as Record<string, unknown>;
    const ports = Array.isArray(service.ports) ? service.ports : [];
    const rewrittenPorts: unknown[] = [];

    for (const port of ports) {
      if (typeof port === "string") {
        const rewritten = rewritePortString(port);
        if (rewritten) {
          rewrittenPorts.push(rewritten);
        }
        continue;
      }

      if (port && typeof port === "object") {
        const structuredPort = port as Record<string, unknown>;
        if (
          typeof structuredPort.published === "number" ||
          typeof structuredPort.published === "string"
        ) {
          rewrittenPorts.push({
            ...structuredPort,
            host_ip: "127.0.0.1"
          });
        }
      }
    }

    if (rewrittenPorts.length > 0) {
      overrideServices[serviceName] = {
        ports: rewrittenPorts
      };
    }
  }

  if (Object.keys(overrideServices).length === 0) {
    return null;
  }

  return YAML.stringify({
    services: overrideServices
  });
}

function renderEnvExample(secretExposure: SecretExposure[]): string | null {
  if (secretExposure.length === 0) {
    return null;
  }

  const keepSecrets = secretExposure
    .filter((entry) => entry.action === "keep")
    .map((entry) => entry.variable);
  const moveSecrets = secretExposure
    .filter((entry) => entry.action !== "keep")
    .map((entry) => entry.variable);

  const lines = [
    "# TraceRoot Audit runtime env template",
    "# Keep only the secrets this approved workflow still needs in the live agent runtime.",
    ""
  ];

  if (keepSecrets.length > 0) {
    lines.push("# Keep in the runtime env");
    for (const variable of keepSecrets) {
      lines.push(`${variable}=`);
    }
    lines.push("");
  }

  if (moveSecrets.length > 0) {
    lines.push("# Review or move out of the runtime env");
    for (const variable of moveSecrets) {
      lines.push(`# ${variable}=`);
    }
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function renderApplyPlan(options: {
  profile: SavedHardeningProfile;
  manifestPath: string;
  envExamplePath: string | null;
  composeOverridePath: string | null;
  composeSourcePath: string | null;
  tapPlanPath: string | null;
  tapWrappers: TapWrapperFile[];
}): string {
  const lines = [
    "# TraceRoot Audit Apply Plan",
    "",
    `- **Approved workflows:** ${options.profile.selectedIntents
      .map((intent) => intent.title)
      .join(", ")}`,
    `- **Approval policy:** ${options.profile.approvalPolicy}`,
    `- **File write policy:** ${options.profile.fileWritePolicy}`,
    `- **Exposure policy:** ${options.profile.exposurePolicy}`,
    "",
    "## Generated files",
    "",
    `- Recommended manifest: \`${path.basename(options.manifestPath)}\``
  ];

  if (options.envExamplePath) {
    lines.push(`- Runtime env template: \`${path.basename(options.envExamplePath)}\``);
  }

  if (options.composeOverridePath && options.composeSourcePath) {
    lines.push(
      `- Compose override: \`${path.basename(options.composeOverridePath)}\` (apply with \`${path.basename(options.composeSourcePath)}\`)`
    );
  }

  if (options.tapPlanPath && options.tapWrappers.length > 0) {
    lines.push(
      `- Action audit guide: \`${path.relative(path.dirname(options.manifestPath), options.tapPlanPath).replace(/\\/g, "/")}\``
    );
  }

  lines.push("", "## Suggested next steps", "");

  lines.push(
    `1. Compare your active manifest with \`${path.basename(options.manifestPath)}\` and carry over the smaller capability set.`
  );

  if (options.envExamplePath) {
    lines.push(
      `2. Create a runtime-only env file from \`${path.basename(options.envExamplePath)}\` and move unrelated secrets out of the live agent env.`
    );
  }

  if (options.composeOverridePath && options.composeSourcePath) {
    lines.push(
      `3. Start your runtime with both compose files: \`docker compose -f ${path.basename(options.composeSourcePath)} -f ${path.basename(options.composeOverridePath)} up -d\`.`
    );
  } else {
    lines.push("3. If your runtime is exposed on the network, bind it to localhost only before running it again.");
  }

  if (options.tapPlanPath && options.tapWrappers.length > 0) {
    lines.push(
      `4. Switch your highest-risk skill/tool commands to the TraceRoot command hooks listed in \`${path.basename(options.tapPlanPath)}\` so runtime actions start leaving an audit trail.`
    );
  }

  lines.push("");

  return `${lines.join("\n")}\n`;
}

interface TapActionSpec {
  action: string;
  severity: AuditSeverity;
  recommendation: string;
}

function classifyTapAction(file: ScannableFile): TapActionSpec | null {
  const relativePath = file.relativePath.toLowerCase();
  const fileName = path.basename(relativePath);
  const combined = `${relativePath}\n${file.content.slice(0, 1200)}`;

  if (/(\.test\.|\.spec\.|__tests__|fixtures?|mocks?)/i.test(relativePath)) {
    return null;
  }

  if (/(stripe|paypal|checkout|payment|purchase|order)/i.test(combined)) {
    return {
      action: "purchase-or-payment",
      severity: "critical",
      recommendation: "Require confirmation before payment-like actions and keep payment secrets out of unrelated runtimes."
    };
  }

  if (/(broker|bank|tradingview|trade|coinbase|binance)/i.test(combined)) {
    return {
      action: "finance-access",
      severity: "critical",
      recommendation: "Require confirmation before finance-related actions and keep broker or banking credentials out of autonomous runtimes."
    };
  }

  if (/(sendgrid|mailgun|nodemailer|smtp|gmail|send-email|mail)/i.test(combined)) {
    return {
      action: "send-email",
      severity: "high-risk",
      recommendation: "Require confirmation before outbound email actions."
    };
  }

  if (/(tweet|twitter|x_api|slack|telegram|whatsapp|discord|post|publish|tiktok|instagram)/i.test(combined)) {
    return {
      action: "publish-or-send-message",
      severity: "high-risk",
      recommendation: "Require confirmation before public posts or outbound messages."
    };
  }

  if (/(rm -rf|unlink|delete|remove|cleanup|archive|writefilesync|fs\.writefile|fs\.rm)/i.test(combined)) {
    return {
      action: "delete-or-modify-files",
      severity: "high-risk",
      recommendation: "Keep destructive file actions behind an explicit approval step."
    };
  }

  if (/\b(fetch|axios|requests?|httpx|curl|wget)\b/i.test(combined) && /\b(fs\.|writefile|readfile)\b/i.test(combined)) {
    return {
      action: `run-${fileName.replace(/\.[^.]+$/, "")}`,
      severity: "risky",
      recommendation: "Review this automation path and keep only the permissions it truly needs."
    };
  }

  return null;
}

function wrapperShellBody(options: {
  rootDir: string;
  file: ScannableFile;
  spec: TapActionSpec;
  surfaceKind: "runtime" | "skill" | "project";
}): string | null {
  const sourcePath = path.join(options.rootDir, options.file.relativePath);
  const normalizedSource = sourcePath.replace(/\\/g, "/");
  const quotedRoot = JSON.stringify(options.rootDir);
  const quotedTarget = JSON.stringify(options.rootDir);
  const quotedAction = JSON.stringify(options.spec.action);
  const quotedSeverity = JSON.stringify(options.spec.severity);
  const quotedRecommendation = JSON.stringify(options.spec.recommendation);
  const quotedSurfaceKind = JSON.stringify(options.surfaceKind);
  const extension = path.extname(options.file.relativePath).toLowerCase();

  const tapPrefix =
    `exec traceroot-audit tap --action ${quotedAction} --severity ${quotedSeverity} --target ${quotedTarget} ` +
    `--surface-kind ${quotedSurfaceKind} --recommendation ${quotedRecommendation} -- `;

  if (extension === ".js" || extension === ".mjs" || extension === ".cjs") {
    return [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      `cd ${quotedRoot}`,
      `${tapPrefix}node ${JSON.stringify(normalizedSource)} "$@"`
    ].join("\n");
  }

  if (extension === ".sh" || extension === ".bash") {
    return [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      `cd ${quotedRoot}`,
      `${tapPrefix}bash ${JSON.stringify(normalizedSource)} "$@"`
    ].join("\n");
  }

  if (extension === ".zsh") {
    return [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      `cd ${quotedRoot}`,
      `${tapPrefix}zsh ${JSON.stringify(normalizedSource)} "$@"`
    ].join("\n");
  }

  if (extension === ".py") {
    return [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      `cd ${quotedRoot}`,
      `${tapPrefix}python3 ${JSON.stringify(normalizedSource)} "$@"`
    ].join("\n");
  }

  if (extension === ".ts") {
    return [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      `cd ${quotedRoot}`,
      'if [ -x "./node_modules/.bin/tsx" ]; then',
      `  ${tapPrefix}./node_modules/.bin/tsx ${JSON.stringify(normalizedSource)} "$@"`,
      "fi",
      'if command -v tsx >/dev/null 2>&1; then',
      `  ${tapPrefix}tsx ${JSON.stringify(normalizedSource)} "$@"`,
      "fi",
      'if command -v ts-node >/dev/null 2>&1; then',
      `  ${tapPrefix}ts-node ${JSON.stringify(normalizedSource)} "$@"`,
      "fi",
      `echo "TraceRoot wrapper could not find tsx or ts-node for ${normalizedSource}" >&2`,
      "exit 127"
    ].join("\n");
  }

  return null;
}

function surfaceKindForProfileSurface(surface: string): "runtime" | "skill" | "project" {
  if (/runtime/i.test(surface)) {
    return "runtime";
  }

  if (/skill|tool|mcp/i.test(surface)) {
    return "skill";
  }

  return "project";
}

async function buildTapWrappers(rootDir: string, profileSurface: string): Promise<{
  tapWrapperDir: string | null;
  tapPlanPath: string | null;
  tapWrappers: TapWrapperFile[];
}> {
  const resolvedTarget = await resolveTarget(rootDir);
  const files = await discoverFiles(resolvedTarget);
  const tapWrappers: TapWrapperFile[] = [];
  const wrapperDir = path.join(rootDir, ".traceroot", "tap");
  const surfaceKind = surfaceKindForProfileSurface(profileSurface);

  for (const file of files) {
    const spec = classifyTapAction(file);
    if (!spec) {
      continue;
    }

    const shellBody = wrapperShellBody({ rootDir, file, spec, surfaceKind });
    if (!shellBody) {
      continue;
    }

    const wrapperName = `${String(tapWrappers.length + 1).padStart(2, "0")}-${spec.action}-${path.basename(file.relativePath).replace(/\.[^.]+$/, "")}.sh`;
    const wrapperPath = path.join(wrapperDir, wrapperName);

    await mkdir(wrapperDir, { recursive: true });
    await writeFile(wrapperPath, `${shellBody}\n`, "utf8");
    await chmod(wrapperPath, 0o755);

    tapWrappers.push({
      action: spec.action,
      severity: spec.severity,
      wrapperPath,
      sourcePath: path.join(rootDir, file.relativePath),
      recommendation: spec.recommendation
    });
  }

  if (tapWrappers.length === 0) {
    return {
      tapWrapperDir: null,
      tapPlanPath: null,
      tapWrappers: []
    };
  }

  const tapPlanPath = path.join(rootDir, "traceroot.tap.plan.md");
  const lines = [
    "# TraceRoot Action Audit Guide",
    "",
    "TraceRoot prepared ready-to-use command hooks for likely high-signal action scripts.",
    "Switch the highest-risk skill/tool commands to these hooks if you want runtime actions to leave a local audit trail.",
    ""
  ];

  for (const wrapper of tapWrappers) {
    lines.push(
      `## ${wrapper.action}`,
      "",
      `- **Risk level:** ${wrapper.severity}`,
      `- **Original script:** \`${path.relative(rootDir, wrapper.sourcePath).replace(/\\/g, "/")}\``,
      `- **TraceRoot command hook:** \`${path.relative(rootDir, wrapper.wrapperPath).replace(/\\/g, "/")}\``,
      `- **Why this matters:** ${wrapper.recommendation}`,
      ""
    );
  }

  await writeFile(tapPlanPath, `${lines.join("\n")}\n`, "utf8");

  return {
    tapWrapperDir: wrapperDir,
    tapPlanPath,
    tapWrappers
  };
}

export async function writeApplyBundle(options: {
  rootDir: string;
  profile: SavedHardeningProfile;
  manifestPathHint: string | null;
}): Promise<ApplyBundleResult> {
  const manifestFormat = recommendedManifestFormat(options.manifestPathHint);
  const manifestPath = manifestOutputPath(options.rootDir, manifestFormat);
  const envExamplePath = path.join(options.rootDir, "traceroot.env.agent.example");
  const planPath = path.join(options.rootDir, "traceroot.apply.plan.md");

  await writeFile(
    manifestPath,
    manifestFormat === "yaml"
      ? YAML.stringify(options.profile.recommendedManifest)
      : `${JSON.stringify(options.profile.recommendedManifest, null, 2)}\n`,
    "utf8"
  );

  const envTemplate = renderEnvExample(options.profile.secretExposure);
  if (envTemplate) {
    await writeFile(envExamplePath, envTemplate, "utf8");
  }

  const composeSourcePath = await findComposeFile(options.rootDir);
  let composeOverridePath: string | null = null;

  if (composeSourcePath) {
    const rawCompose = await readFile(composeSourcePath, "utf8");
    const override = buildComposeOverride(rawCompose);

    if (override) {
      composeOverridePath = path.join(
        options.rootDir,
        "docker-compose.traceroot.override.yml"
      );
      await writeFile(composeOverridePath, override, "utf8");
    }
  }

  const tapBundle = await buildTapWrappers(options.rootDir, options.profile.surface);

  await writeFile(
    planPath,
    renderApplyPlan({
      profile: options.profile,
      manifestPath,
      envExamplePath: envTemplate ? envExamplePath : null,
      composeOverridePath,
      composeSourcePath,
      tapPlanPath: tapBundle.tapPlanPath,
      tapWrappers: tapBundle.tapWrappers
    }),
    "utf8"
  );

  return {
    rootDir: options.rootDir,
    planPath,
    manifestPath,
    envExamplePath: envTemplate ? envExamplePath : null,
    composeOverridePath,
    composeSourcePath,
    keptSecrets: options.profile.secretExposure
      .filter((entry) => entry.action === "keep")
      .map((entry) => entry.variable),
    movedSecrets: options.profile.secretExposure
      .filter((entry) => entry.action !== "keep")
      .map((entry) => entry.variable),
    tapWrapperDir: tapBundle.tapWrapperDir,
    tapPlanPath: tapBundle.tapPlanPath,
    tapWrappers: tapBundle.tapWrappers
  };
}
