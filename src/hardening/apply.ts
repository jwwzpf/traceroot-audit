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
  tapInstallBackupPath: string | null;
  tapInstalledCommands: TapInstalledCommand[];
}

export interface TapWrapperFile {
  action: string;
  severity: AuditSeverity;
  wrapperPath: string;
  launchCommand: string;
  sourcePath: string;
  recommendation: string;
  entrypoints: TapEntrypoint[];
}

export interface TapEntrypoint {
  kind: "npm-script" | "bin";
  name: string;
  currentCommand: string;
  suggestedCommand: string;
  installStatus: "manual" | "installed" | "already-installed";
}

export interface TapInstalledCommand {
  kind: "npm-script" | "bin";
  name: string;
  beforeCommand: string;
  afterCommand: string;
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
  tapInstalledCommands: TapInstalledCommand[];
}): string {
  const lines = [
    "# TraceRoot 应用说明",
    "",
    `- **你刚才批准的工作流：** ${options.profile.selectedIntents
      .map((intent) => intent.title)
      .join(", ")}`,
    `- **审批方式：** ${options.profile.approvalPolicy}`,
    `- **文件写入范围：** ${options.profile.fileWritePolicy}`,
    `- **网络暴露范围：** ${options.profile.exposurePolicy}`,
    "",
    "## TraceRoot 已经帮你准备好的内容",
    "",
    `- 更小权限的 manifest 建议：\`${path.basename(options.manifestPath)}\``
  ];

  if (options.envExamplePath) {
    lines.push(`- 更干净的运行时环境变量模板：\`${path.basename(options.envExamplePath)}\``);
  }

  if (options.composeOverridePath && options.composeSourcePath) {
    lines.push(
      `- 更安全的 compose 覆盖文件：\`${path.basename(options.composeOverridePath)}\`（和 \`${path.basename(options.composeSourcePath)}\` 一起用）`
    );
  }

  if (options.tapPlanPath && options.tapWrappers.length > 0) {
    if (options.tapInstalledCommands.length > 0) {
      lines.push(
        `- 动作审计说明：\`${path.relative(path.dirname(options.manifestPath), options.tapPlanPath).replace(/\\/g, "/")}\`（常见启动命令已经帮你接好）`
      );
    } else {
      lines.push(
        `- 动作审计说明：\`${path.relative(path.dirname(options.manifestPath), options.tapPlanPath).replace(/\\/g, "/")}\``
      );
    }
  }

  lines.push("", "## 接下来最值得先做的事", "");

  lines.push(
    `1. 先把你正在使用的 manifest 和 \`${path.basename(options.manifestPath)}\` 对照一下，把更小的能力范围同步进去。`
  );

  if (options.envExamplePath) {
    lines.push(
      `2. 按 \`${path.basename(options.envExamplePath)}\` 整理一份只给 runtime 用的环境变量，把当前工作流根本用不到的 secrets 挪出去。`
    );
  }

  if (options.composeOverridePath && options.composeSourcePath) {
    lines.push(
      `3. 用两份 compose 一起重启 runtime：\`docker compose -f ${path.basename(options.composeSourcePath)} -f ${path.basename(options.composeOverridePath)} up -d\`。`
    );
  } else {
    lines.push("3. 如果 runtime 现在能被局域网或外部访问，下一次启动前尽量把它收回到 localhost。");
  }

  if (options.tapPlanPath && options.tapWrappers.length > 0) {
    if (options.tapInstalledCommands.length > 0) {
      lines.push(
        `4. 动作审计这一步常见命令已经帮你接好了。你继续照常运行原来的命令，TraceRoot 就会开始记审计记录。`
      );
    } else {
      lines.push(
        `4. 打开 \`${path.basename(options.tapPlanPath)}\`，TraceRoot 已经帮你挑出最值得先接入审计的高风险动作。`
      );
    }
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

interface TapInstallResult {
  backupPath: string | null;
  installedCommands: TapInstalledCommand[];
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

function runnerModuleBody(): string {
  return `#!/usr/bin/env node
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

function now() {
  return new Date().toISOString();
}

function iconForSeverity(severity) {
  if (severity === "critical") return "🚨";
  if (severity === "high-risk") return "🛑";
  if (severity === "risky") return "⚠️";
  return "🟢";
}

async function appendEvents(events) {
  const auditDir = path.join(os.homedir(), ".traceroot", "audit");
  const eventsPath = path.join(auditDir, "events.jsonl");
  await fs.mkdir(auditDir, { recursive: true });
  const content = events.map((event) => JSON.stringify(event)).join("\\n") + "\\n";
  await fs.appendFile(eventsPath, content, "utf8");
}

function runCommand(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: "inherit",
      env: process.env,
      cwd
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({ code: code ?? 1, signal });
    });
  });
}

export async function runTraceRootAction(config) {
  const commandArgs = process.argv.slice(2);
  const target = config.target ?? process.cwd();
  const attemptedMessage = config.message ?? \`Agent 正在尝试执行一个动作：\${config.action}\`;

  console.log(
    [
      \`\${iconForSeverity(config.severity)} TraceRoot 动作审计\`,
      \`🧩 动作：\${config.action}\`,
      \`🎯 Target：\${target}\`
    ].join("\\n")
  );

  await appendEvents([
    {
      timestamp: now(),
      severity: config.severity,
      category: "action-event",
      source: "tap-wrapper",
      target,
      surfaceKind: config.surfaceKind,
      action: config.action,
      status: "attempted",
      message: attemptedMessage,
      recommendation: config.recommendation,
      evidence: { args: commandArgs }
    }
  ]);

  let lastError = null;

  for (const candidate of config.candidates) {
    const args = [...candidate.args, ...commandArgs];
    try {
      const result = await runCommand(candidate.command, args, target);
      const succeeded = result.code === 0;
      await appendEvents([
        {
          timestamp: now(),
          severity: succeeded ? "safe" : config.severity,
          category: "action-event",
          source: "tap-wrapper",
          target,
          surfaceKind: config.surfaceKind,
          action: config.action,
          status: succeeded ? "succeeded" : "failed",
          message: succeeded
            ? \`Agent 动作执行成功：\${config.action}\`
            : \`Agent 动作执行失败：\${config.action}\`,
          recommendation: succeeded
            ? undefined
            : config.recommendation,
          evidence: {
            command: candidate.command,
            args,
            exitCode: result.code,
            signal: result.signal
          }
        }
      ]);
      console.log(\`\${succeeded ? "✅" : "❌"} TraceRoot 已经记下这次动作：\${config.action}\${succeeded ? "（成功）" : "（失败）"}\`);
      process.exitCode = result.code;
      return;
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
        lastError = error;
        continue;
      }
      lastError = error;
      break;
    }
  }

  const errorMessage =
    lastError && typeof lastError === "object" && "message" in lastError
      ? String(lastError.message)
      : "没有找到可用的解释器或运行命令。";

  await appendEvents([
    {
      timestamp: now(),
      severity: config.severity,
      category: "action-event",
      source: "tap-wrapper",
      target,
      surfaceKind: config.surfaceKind,
      action: config.action,
      status: "failed",
      message: \`Agent 动作还没来得及执行就失败了：\${config.action}\`,
      recommendation: config.recommendation,
      evidence: { error: errorMessage }
    }
  ]);

  console.error(\`❌ TraceRoot 没能替这个动作完成审计接入：\${errorMessage}\`);
  process.exitCode = 1;
}
`;
}

function wrapperModuleBody(options: {
  rootDir: string;
  file: ScannableFile;
  spec: TapActionSpec;
  surfaceKind: "runtime" | "skill" | "project";
}): string | null {
  const sourcePath = path.join(options.rootDir, options.file.relativePath);
  const normalizedSource = sourcePath.replace(/\\/g, "/");
  const quotedTarget = JSON.stringify(options.rootDir);
  const quotedAction = JSON.stringify(options.spec.action);
  const quotedSeverity = JSON.stringify(options.spec.severity);
  const quotedRecommendation = JSON.stringify(options.spec.recommendation);
  const quotedSurfaceKind = JSON.stringify(options.surfaceKind);
  const extension = path.extname(options.file.relativePath).toLowerCase();
  const runnerImport = JSON.stringify("./_runner.mjs");
  let candidates: Array<{ command: string; args: string[] }> | null = null;

  if (extension === ".js" || extension === ".mjs" || extension === ".cjs") {
    candidates = [{ command: "node", args: [normalizedSource] }];
  }

  if (extension === ".sh" || extension === ".bash") {
    candidates = [
      { command: "bash", args: [normalizedSource] },
      { command: "sh", args: [normalizedSource] }
    ];
  }

  if (extension === ".zsh") {
    candidates = [
      { command: "zsh", args: [normalizedSource] },
      { command: "bash", args: [normalizedSource] }
    ];
  }

  if (extension === ".py") {
    candidates = [
      { command: "python3", args: [normalizedSource] },
      { command: "python", args: [normalizedSource] },
      { command: "py", args: ["-3", normalizedSource] }
    ];
  }

  if (extension === ".ts") {
    candidates = [
      { command: "./node_modules/.bin/tsx", args: [normalizedSource] },
      { command: "./node_modules/.bin/tsx.cmd", args: [normalizedSource] },
      { command: "tsx", args: [normalizedSource] },
      { command: "ts-node", args: [normalizedSource] }
    ];
  }

  if (!candidates) {
    return null;
  }

  return `#!/usr/bin/env node
import { runTraceRootAction } from ${runnerImport};

await runTraceRootAction({
  action: ${quotedAction},
  severity: ${quotedSeverity},
  target: ${quotedTarget},
  surfaceKind: ${quotedSurfaceKind},
  recommendation: ${quotedRecommendation},
  candidates: ${JSON.stringify(candidates, null, 2)}
});
`;
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
  wrapperLaunchCommand: string;
  sourceRelativePath: string;
  candidates: PackageEntrypointCandidate[];
}): TapEntrypoint[] {
  const sourceRelativePath = options.sourceRelativePath.replace(/\\/g, "/");

  return options.candidates
    .filter((candidate) => matchesEntrypointCommand(candidate.command, sourceRelativePath))
    .map((candidate) => {
      if (candidate.kind === "npm-script") {
        return {
          kind: candidate.kind,
          name: candidate.name,
          currentCommand: candidate.command,
          suggestedCommand: options.wrapperLaunchCommand,
          installStatus: "manual"
        };
      }

      return {
        kind: candidate.kind,
        name: candidate.name,
        currentCommand: candidate.command,
        suggestedCommand: options.wrapperLaunchCommand,
        installStatus: "manual"
      };
    });
}

async function installTapEntrypoints(options: {
  rootDir: string;
  tapWrappers: TapWrapperFile[];
}): Promise<TapInstallResult> {
  const packageJsonPath = path.join(options.rootDir, "package.json");

  let rawPackageJson: string;

  try {
    rawPackageJson = await readFile(packageJsonPath, "utf8");
  } catch {
    return {
      backupPath: null,
      installedCommands: []
    };
  }

  let parsedPackageJson: {
    scripts?: Record<string, unknown>;
    [key: string]: unknown;
  };

  try {
    parsedPackageJson = JSON.parse(rawPackageJson) as {
      scripts?: Record<string, unknown>;
      [key: string]: unknown;
    };
  } catch {
    return {
      backupPath: null,
      installedCommands: []
    };
  }

  if (!parsedPackageJson.scripts || typeof parsedPackageJson.scripts !== "object") {
    return {
      backupPath: null,
      installedCommands: []
    };
  }

  const groupedEntrypoints = new Map<
    string,
    Array<{ wrapper: TapWrapperFile; entrypoint: TapEntrypoint }>
  >();

  for (const wrapper of options.tapWrappers) {
    for (const entrypoint of wrapper.entrypoints) {
      if (entrypoint.kind !== "npm-script") {
        continue;
      }

      const existing = groupedEntrypoints.get(entrypoint.name) ?? [];
      existing.push({ wrapper, entrypoint });
      groupedEntrypoints.set(entrypoint.name, existing);
    }
  }

  const installedCommands: TapInstalledCommand[] = [];

  for (const [scriptName, candidates] of groupedEntrypoints.entries()) {
    if (candidates.length !== 1) {
      continue;
    }

    const [{ entrypoint }] = candidates;
    const currentValue = parsedPackageJson.scripts[scriptName];

    if (typeof currentValue !== "string") {
      continue;
    }

    if (currentValue === entrypoint.suggestedCommand) {
      entrypoint.installStatus = "already-installed";
      installedCommands.push({
        kind: entrypoint.kind,
        name: entrypoint.name,
        beforeCommand: currentValue,
        afterCommand: currentValue
      });
      continue;
    }

    if (currentValue !== entrypoint.currentCommand) {
      continue;
    }

    parsedPackageJson.scripts[scriptName] = entrypoint.suggestedCommand;
    entrypoint.installStatus = "installed";
    installedCommands.push({
      kind: entrypoint.kind,
      name: entrypoint.name,
      beforeCommand: entrypoint.currentCommand,
      afterCommand: entrypoint.suggestedCommand
    });
  }

  if (installedCommands.length === 0) {
    return {
      backupPath: null,
      installedCommands: []
    };
  }

  const backupDir = path.join(options.rootDir, ".traceroot", "backups");
  const backupPath = path.join(backupDir, "package.json.before-action-audit.json");
  await mkdir(backupDir, { recursive: true });
  await writeFile(backupPath, rawPackageJson, "utf8");
  await writeFile(`${packageJsonPath}`, `${JSON.stringify(parsedPackageJson, null, 2)}\n`, "utf8");

  return {
    backupPath,
    installedCommands
  };
}

async function buildTapWrappers(rootDir: string, profileSurface: string): Promise<{
  tapWrapperDir: string | null;
  tapPlanPath: string | null;
  tapWrappers: TapWrapperFile[];
  tapInstallBackupPath: string | null;
  tapInstalledCommands: TapInstalledCommand[];
}> {
  const resolvedTarget = await resolveTarget(rootDir);
  const files = await discoverFiles(resolvedTarget);
  const tapWrappers: TapWrapperFile[] = [];
  const wrapperDir = path.join(rootDir, ".traceroot", "tap");
  const runnerPath = path.join(wrapperDir, "_runner.mjs");
  const surfaceKind = surfaceKindForProfileSurface(profileSurface);
  const packageEntrypoints = await detectPackageEntrypoints(rootDir);

  await mkdir(wrapperDir, { recursive: true });
  await writeFile(runnerPath, `${runnerModuleBody()}\n`, "utf8");

  for (const file of files) {
    const spec = classifyTapAction(file);
    if (!spec) {
      continue;
    }

    const wrapperBody = wrapperModuleBody({ rootDir, file, spec, surfaceKind });
    if (!wrapperBody) {
      continue;
    }

    const wrapperName = `${String(tapWrappers.length + 1).padStart(2, "0")}-${spec.action}-${path.basename(file.relativePath).replace(/\.[^.]+$/, "")}.mjs`;
    const wrapperPath = path.join(wrapperDir, wrapperName);
    const wrapperRelativePath = path.relative(rootDir, wrapperPath).replace(/\\/g, "/");
    const launchCommand = `node ${wrapperRelativePath}`;

    await writeFile(wrapperPath, `${wrapperBody}\n`, "utf8");
    await chmod(wrapperPath, 0o755);

    tapWrappers.push({
      action: spec.action,
      severity: spec.severity,
      wrapperPath,
      launchCommand,
      sourcePath: path.join(rootDir, file.relativePath),
      recommendation: spec.recommendation,
      entrypoints: buildSuggestedEntrypoints({
        rootDir,
        wrapperLaunchCommand: launchCommand,
        sourceRelativePath: file.relativePath,
        candidates: packageEntrypoints
      })
    });
  }

  if (tapWrappers.length === 0) {
    return {
      tapWrapperDir: null,
      tapPlanPath: null,
      tapWrappers: [],
      tapInstallBackupPath: null,
      tapInstalledCommands: []
    };
  }

  const tapInstallResult = await installTapEntrypoints({
    rootDir,
    tapWrappers
  });

  const tapPlanPath = path.join(rootDir, "traceroot.tap.plan.md");
  const lines = [
    "# TraceRoot 动作审计说明",
    "",
    "TraceRoot 已经帮你找到了几个最值得先接入审计的动作。",
    tapInstallResult.installedCommands.length > 0
      ? `TraceRoot 已经自动帮你接好了 ${tapInstallResult.installedCommands.length} 个常见启动命令。以后你还是照常运行原来的命令就行。`
      : "你不用自己研究怎么接。做法很简单：把你平时启动这个动作的命令，换成下面 TraceRoot 给你准备好的接入文件。",
    "",
    "换完以后，TraceRoot 就能：",
    "- 记住这个动作什么时候开始、有没有成功",
    "- 把高风险动作单独标出来",
    "- 让你之后用 `traceroot-audit logs` 回看这条审计记录",
    ""
  ];

  if (tapInstallResult.backupPath) {
    lines.push(
      `原来的 package.json 我们也已经帮你备份好了：\`${path.relative(rootDir, tapInstallResult.backupPath).replace(/\\/g, "/")}\``,
      ""
    );
  }

  for (const wrapper of tapWrappers) {
    lines.push(
      `## ${wrapper.action}`,
      "",
      `- **风险级别：** ${wrapper.severity}`,
      `- **原始脚本：** \`${path.relative(rootDir, wrapper.sourcePath).replace(/\\/g, "/")}\``,
      `- **TraceRoot 给你准备好的接入文件：** \`${path.relative(rootDir, wrapper.wrapperPath).replace(/\\/g, "/")}\``,
      `- **如果你要手动接入，直接用这个命令：** \`${wrapper.launchCommand}\``,
      `- **为什么值得先接它：** ${wrapper.recommendation}`,
      ""
    );

    if (wrapper.entrypoints.length > 0) {
      lines.push("### 你现在就可以这样改", "");

      for (const entrypoint of wrapper.entrypoints) {
        if (entrypoint.kind === "npm-script") {
          if (entrypoint.installStatus === "installed") {
            lines.push(
              `- 你以后还是照常运行：\`npm run ${entrypoint.name}\``,
              `- TraceRoot 已经帮你接好了：它现在会先经过 \`${entrypoint.suggestedCommand}\` 再执行原来的动作`,
              "- 你不用手动改任何东西了。",
              ""
            );
            continue;
          }

          if (entrypoint.installStatus === "already-installed") {
            lines.push(
              `- 这个命令已经接好了：\`npm run ${entrypoint.name}\``,
              `- 它现在已经是 TraceRoot 的接入路径：\`${entrypoint.suggestedCommand}\``,
              "- 你继续像以前一样运行它就可以了。",
              ""
            );
            continue;
          }

          lines.push(
            `- 你现在平时运行的是：\`npm run ${entrypoint.name}\``,
            `- 它背后实际执行的是：\`${entrypoint.currentCommand}\``,
            `- 如果你愿意手动接上，也可以把 \`scripts.${entrypoint.name}\` 换成 \`${entrypoint.suggestedCommand}\``,
            "- 接上以后，这个动作每次运行时，TraceRoot 都能替你留下审计记录。",
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
        `- 如果你的 runtime 或 skill 配置里现在直接写的是 \`${path.relative(rootDir, wrapper.sourcePath).replace(/\\/g, "/")}\`，就把它换成：\`${wrapper.launchCommand}\`。`,
        "- 改完以后，这个动作每次运行时，TraceRoot 都能替你留下审计记录。",
        ""
      );
    }
  }

  await writeFile(tapPlanPath, `${lines.join("\n")}\n`, "utf8");

  return {
    tapWrapperDir: wrapperDir,
    tapPlanPath,
    tapWrappers,
    tapInstallBackupPath: tapInstallResult.backupPath,
    tapInstalledCommands: tapInstallResult.installedCommands
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
      tapWrappers: tapBundle.tapWrappers,
      tapInstalledCommands: tapBundle.tapInstalledCommands
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
    tapWrappers: tapBundle.tapWrappers,
    tapInstallBackupPath: tapBundle.tapInstallBackupPath,
    tapInstalledCommands: tapBundle.tapInstalledCommands
  };
}
