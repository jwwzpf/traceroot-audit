import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import fg from "fast-glob";
import YAML from "yaml";

import { recommendedManifestFormat } from "./analysis";
import type { SavedHardeningProfile } from "./profile";
import type { SecretExposure } from "./analysis";

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

  lines.push("");

  return `${lines.join("\n")}\n`;
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

  await writeFile(
    planPath,
    renderApplyPlan({
      profile: options.profile,
      manifestPath,
      envExamplePath: envTemplate ? envExamplePath : null,
      composeOverridePath,
      composeSourcePath
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
      .map((entry) => entry.variable)
  };
}
