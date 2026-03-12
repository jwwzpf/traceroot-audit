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
  entrypoints: TapEntrypoint[];
}

export interface TapEntrypoint {
  kind: "npm-script" | "bin";
  name: string;
  currentCommand: string;
  suggestedCommand: string;
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

interface PackageEntrypointCandidate {
  kind: "npm-script" | "bin";
  name: string;
  command: string;
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
      recommendation: "这类动作会碰到付款或下单，应该强制人工确认，并把支付类 secrets 留在 runtime 外面。"
    };
  }

  if (/(broker|bank|tradingview|trade|coinbase|binance)/i.test(combined)) {
    return {
      action: "finance-access",
      severity: "critical",
      recommendation: "这类动作会碰到交易、券商或银行数据，应该强制人工确认，并把金融类凭证放在 autonomous runtime 外面。"
    };
  }

  if (/(sendgrid|mailgun|nodemailer|smtp|gmail|send-email|mail)/i.test(combined)) {
    return {
      action: "send-email",
      severity: "high-risk",
      recommendation: "这类动作会对外发邮件，最好先让用户确认，再真正发出去。"
    };
  }

  if (/(tweet|twitter|x_api|slack|telegram|whatsapp|discord|post|publish|tiktok|instagram)/i.test(combined)) {
    return {
      action: "publish-or-send-message",
      severity: "high-risk",
      recommendation: "这类动作会公开发帖或向外发消息，最好先让用户确认，再真正发出去。"
    };
  }

  if (/(rm -rf|unlink|delete|remove|cleanup|archive|writefilesync|fs\.writefile|fs\.rm)/i.test(combined)) {
    return {
      action: "delete-or-modify-files",
      severity: "high-risk",
      recommendation: "这类动作会删文件或改文件，最好放在明确的人工确认之后。"
    };
  }

  if (/\b(fetch|axios|requests?|httpx|curl|wget)\b/i.test(combined) && /\b(fs\.|writefile|readfile)\b/i.test(combined)) {
    return {
      action: `run-${fileName.replace(/\.[^.]+$/, "")}`,
      severity: "risky",
      recommendation: "这条自动化链路同时会联网和碰文件，最好再收一下权限，只保留真正需要的能力。"
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

async function detectPackageEntrypoints(rootDir: string): Promise<PackageEntrypointCandidate[]> {
  const packageJsonPath = path.join(rootDir, "package.json");

  try {
    const content = await readFile(packageJsonPath, "utf8");
    const parsed = JSON.parse(content) as {
      scripts?: Record<string, unknown>;
      bin?: string | Record<string, unknown>;
    };
    const candidates: PackageEntrypointCandidate[] = [];

    if (parsed.scripts && typeof parsed.scripts === "object") {
      for (const [name, value] of Object.entries(parsed.scripts)) {
        if (typeof value !== "string") {
          continue;
        }

        candidates.push({
          kind: "npm-script",
          name,
          command: value
        });
      }
    }

    if (typeof parsed.bin === "string") {
      candidates.push({
        kind: "bin",
        name: path.basename(rootDir),
        command: parsed.bin
      });
    } else if (parsed.bin && typeof parsed.bin === "object") {
      for (const [name, value] of Object.entries(parsed.bin)) {
        if (typeof value !== "string") {
          continue;
        }

        candidates.push({
          kind: "bin",
          name,
          command: value
        });
      }
    }

    return candidates;
  } catch {
    return [];
  }
}

function matchesEntrypointCommand(command: string, relativePath: string): boolean {
  const normalizedCommand = command.replace(/\\/g, "/").toLowerCase();
  const normalizedRelativePath = relativePath.replace(/\\/g, "/").toLowerCase();
  const prefixedPath = `./${normalizedRelativePath}`;
  const fileName = path.basename(normalizedRelativePath);

  return (
    normalizedCommand.includes(normalizedRelativePath) ||
    normalizedCommand.includes(prefixedPath) ||
    normalizedCommand.includes(fileName)
  );
}

function buildSuggestedEntrypoints(options: {
  rootDir: string;
  wrapperPath: string;
  sourceRelativePath: string;
  candidates: PackageEntrypointCandidate[];
}): TapEntrypoint[] {
  const wrapperRelativePath = path.relative(options.rootDir, options.wrapperPath).replace(/\\/g, "/");
  const sourceRelativePath = options.sourceRelativePath.replace(/\\/g, "/");

  return options.candidates
    .filter((candidate) => matchesEntrypointCommand(candidate.command, sourceRelativePath))
    .map((candidate) => {
      if (candidate.kind === "npm-script") {
        return {
          kind: candidate.kind,
          name: candidate.name,
          currentCommand: candidate.command,
          suggestedCommand: wrapperRelativePath
        };
      }

      return {
        kind: candidate.kind,
        name: candidate.name,
        currentCommand: candidate.command,
        suggestedCommand: wrapperRelativePath
      };
    });
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
  const packageEntrypoints = await detectPackageEntrypoints(rootDir);

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
      recommendation: spec.recommendation,
      entrypoints: buildSuggestedEntrypoints({
        rootDir,
        wrapperPath,
        sourceRelativePath: file.relativePath,
        candidates: packageEntrypoints
      })
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
    "# TraceRoot 动作审计说明",
    "",
    "TraceRoot 已经帮你找到了几个最值得先接入审计的动作。",
    "你不用自己研究怎么接。做法很简单：把你平时启动这个动作的命令，换成下面 TraceRoot 给你准备好的接入文件。",
    "",
    "换完以后，TraceRoot 就能：",
    "- 记住这个动作什么时候开始、有没有成功",
    "- 把高风险动作单独标出来",
    "- 让你之后用 `traceroot-audit logs` 回看这条审计记录",
    ""
  ];

  for (const wrapper of tapWrappers) {
    lines.push(
      `## ${wrapper.action}`,
      "",
      `- **风险级别：** ${wrapper.severity}`,
      `- **原始脚本：** \`${path.relative(rootDir, wrapper.sourcePath).replace(/\\/g, "/")}\``,
      `- **TraceRoot 给你准备好的接入文件：** \`${path.relative(rootDir, wrapper.wrapperPath).replace(/\\/g, "/")}\``,
      `- **为什么值得先接它：** ${wrapper.recommendation}`,
      ""
    );

    if (wrapper.entrypoints.length > 0) {
      lines.push("### 你现在就可以这样改", "");

      for (const entrypoint of wrapper.entrypoints) {
        if (entrypoint.kind === "npm-script") {
          lines.push(
            `- 你现在平时运行的是：\`npm run ${entrypoint.name}\``,
            `- 它背后实际执行的是：\`${entrypoint.currentCommand}\``,
            `- 建议你改成：把 \`scripts.${entrypoint.name}\` 换成 \`${entrypoint.suggestedCommand}\``,
            "- 改完以后，这个动作每次运行时，TraceRoot 都能替你留下审计记录。",
            ""
          );
          continue;
        }

        lines.push(
          `- 你现在平时用的是这个命令入口：\`${entrypoint.name}\``,
          `- 它现在指向：\`${entrypoint.currentCommand}\``,
          `- 建议你改成：让它指向 \`${entrypoint.suggestedCommand}\``,
          "- 改完以后，这个动作每次运行时，TraceRoot 都能替你留下审计记录。",
          ""
        );
      }
    } else {
      lines.push(
        "### 你现在就可以这样改",
        "",
        `- 如果你的 runtime 或 skill 配置里直接写的是 \`${path.relative(rootDir, wrapper.sourcePath).replace(/\\/g, "/")}\`，就把它换成上面的 TraceRoot 接入文件。`,
        "- 改完以后，这个动作每次运行时，TraceRoot 都能替你留下审计记录。",
        ""
      );
    }
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
