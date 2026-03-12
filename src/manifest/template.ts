import { access, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import YAML from "yaml";

import { resolveTarget } from "../utils/files";
import type { TraceRootManifest } from "./schema";

export type ManifestFormat = "json" | "yaml";

interface PackageJsonLike {
  name?: unknown;
  version?: unknown;
  author?: unknown;
  homepage?: unknown;
  repository?: unknown;
}

export interface InitManifestResult {
  manifest: TraceRootManifest;
  manifestFilePath: string;
  manifestRelativePath: string;
}

export interface WriteManifestOptions {
  format: ManifestFormat;
  force: boolean;
}

export async function writeManifestTemplate(
  targetInput: string,
  options: WriteManifestOptions
): Promise<InitManifestResult> {
  const resolvedTarget = await resolveTarget(targetInput);
  const targetDir =
    resolvedTarget.type === "directory"
      ? resolvedTarget.absolutePath
      : resolvedTarget.rootDir;
  const manifestRelativePath =
    options.format === "json"
      ? "traceroot.manifest.json"
      : "traceroot.manifest.yaml";
  const manifestFilePath = path.join(targetDir, manifestRelativePath);

  if (!options.force) {
    try {
      await access(manifestFilePath);
      throw new Error(
        `Manifest already exists at ${manifestRelativePath}. Re-run with --force to overwrite it.`
      );
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("Re-run with --force to overwrite it.")
      ) {
        throw error;
      }
    }
  }

  const manifest = await buildManifestTemplate(targetDir);
  const content =
    options.format === "json"
      ? `${JSON.stringify(manifest, null, 2)}\n`
      : YAML.stringify(manifest);

  await writeFile(manifestFilePath, content, "utf8");

  return {
    manifest,
    manifestFilePath,
    manifestRelativePath
  };
}

export async function buildManifestTemplate(targetDir: string): Promise<TraceRootManifest> {
  const packageJson = await loadPackageJson(targetDir);
  const repositoryUrl = extractRepositoryUrl(packageJson?.repository);
  const homepageUrl = asNonEmptyString(packageJson?.homepage);
  const source =
    homepageUrl ?? repositoryUrl ?? "https://example.com/replace-with-source";

  return {
    name: asNonEmptyString(packageJson?.name) ?? path.basename(targetDir),
    version: asNonEmptyString(packageJson?.version) ?? "0.1.0",
    author:
      normalizeAuthor(packageJson?.author) ??
      process.env.USER ??
      process.env.USERNAME ??
      "unknown-author",
    source,
    capabilities: [],
    risk_level: "medium",
    side_effects: false,
    idempotency: "unknown",
    interrupt_support: "unknown",
    confirmation_required: false,
    safeguards: []
  };
}

async function loadPackageJson(targetDir: string): Promise<PackageJsonLike | null> {
  const packageJsonPath = path.join(targetDir, "package.json");

  try {
    const content = await readFile(packageJsonPath, "utf8");
    return JSON.parse(content) as PackageJsonLike;
  } catch {
    return null;
  }
}

function asNonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function normalizeAuthor(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }

  if (
    value &&
    typeof value === "object" &&
    "name" in value &&
    typeof value.name === "string" &&
    value.name.trim().length > 0
  ) {
    return value.name.trim();
  }

  return undefined;
}

function extractRepositoryUrl(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim().length > 0) {
    return normalizeRepositoryUrl(value.trim());
  }

  if (
    value &&
    typeof value === "object" &&
    "url" in value &&
    typeof value.url === "string" &&
    value.url.trim().length > 0
  ) {
    return normalizeRepositoryUrl(value.url.trim());
  }

  return undefined;
}

function normalizeRepositoryUrl(value: string): string | undefined {
  if (value.startsWith("git+")) {
    return normalizeRepositoryUrl(value.slice(4));
  }

  if (value.startsWith("git@github.com:")) {
    const repoPath = value.replace("git@github.com:", "").replace(/\.git$/, "");
    return `https://github.com/${repoPath}`;
  }

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value.replace(/\.git$/, "");
  }

  return undefined;
}
