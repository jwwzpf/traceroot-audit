import { access, readFile, stat } from "node:fs/promises";
import path from "node:path";

import fg from "fast-glob";

import type { ScannableFile, ScanTargetType } from "../rules/types";
import { relativeToRoot } from "./paths";

const discoveryPatterns = [
  "**/.env",
  "**/.env.*",
  "**/docker-compose*.yml",
  "**/docker-compose*.yaml",
  "**/*.{json,yaml,yml,sh,bash,zsh,js,ts,py}"
];

const ignorePatterns = [
  "**/.git/**",
  "**/node_modules/**",
  "**/dist/**",
  "**/coverage/**",
  "**/.turbo/**",
  "**/.next/**",
  "**/.output/**",
  "**/traceroot.baseline.json"
];

const traceRootIgnoreFile = ".tracerootignore";

export interface ResolvedTarget {
  absolutePath: string;
  rootDir: string;
  type: ScanTargetType;
}

export async function resolveTarget(targetInput: string): Promise<ResolvedTarget> {
  const absolutePath = path.resolve(targetInput);
  let targetStat;

  try {
    targetStat = await stat(absolutePath);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Target path could not be resolved.";
    throw new Error(`Unable to scan "${targetInput}": ${message}`);
  }

  if (targetStat.isDirectory()) {
    return {
      absolutePath,
      rootDir: absolutePath,
      type: "directory"
    };
  }

  if (targetStat.isFile()) {
    return {
      absolutePath,
      rootDir: path.dirname(absolutePath),
      type: "file"
    };
  }

  throw new Error(`Unable to scan "${targetInput}": target must be a file or directory.`);
}

async function buildScannableFile(
  rootDir: string,
  absolutePath: string
): Promise<ScannableFile> {
  const content = await readFile(absolutePath, "utf8");

  return {
    absolutePath,
    relativePath: relativeToRoot(rootDir, absolutePath),
    extension: path.extname(absolutePath).toLowerCase(),
    content
  };
}

export async function discoverFiles(
  target: ResolvedTarget
): Promise<ScannableFile[]> {
  if (target.type === "file") {
    return [await buildScannableFile(target.rootDir, target.absolutePath)];
  }

  const userIgnorePatterns = await loadTraceRootIgnorePatterns(target.rootDir);

  const relativePaths = await fg(discoveryPatterns, {
    cwd: target.rootDir,
    dot: true,
    onlyFiles: true,
    unique: true,
    ignore: [...ignorePatterns, ...userIgnorePatterns]
  });

  return Promise.all(
    relativePaths
      .sort((left, right) => left.localeCompare(right))
      .map((relativePath) =>
        buildScannableFile(target.rootDir, path.join(target.rootDir, relativePath))
      )
  );
}

async function loadTraceRootIgnorePatterns(rootDir: string): Promise<string[]> {
  const ignoreFilePath = path.join(rootDir, traceRootIgnoreFile);

  try {
    await access(ignoreFilePath);
  } catch {
    return [];
  }

  const content = await readFile(ignoreFilePath, "utf8");

  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}
