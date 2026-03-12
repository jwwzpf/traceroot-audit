import { access, realpath, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import fg from "fast-glob";

import { loadManifest } from "../manifest/loader";
import type { ScanTargetType } from "../rules/types";
import { discoverFiles, resolveTarget } from "../utils/files";
import { analyzeSurface, type ScanSurfaceKind, type SuggestedScanTarget, type SurfaceConfidence, type SurfaceDetection } from "./surfaces";

export interface DiscoveryResult {
  target: string;
  targetPath: string;
  rootDir: string;
  targetType: ScanTargetType;
  surface: SurfaceDetection;
  manifestPath: string | null;
  manifestError?: string;
  filesDiscovered: number;
  manifestFiles: string[];
  envFiles: string[];
  runtimeConfigFiles: string[];
  scriptFiles: string[];
  suggestedTargets: SuggestedScanTarget[];
}

export interface DiscoverySummaryJson {
  target: string;
  targetPath: string;
  rootDir: string;
  targetType: ScanTargetType;
  surface: {
    kind: ScanSurfaceKind;
    label: string;
    confidence: SurfaceConfidence;
    reasons: string[];
  };
  manifestPath: string | null;
  filesDiscovered: number;
  manifestFiles: string[];
  envFiles: string[];
  runtimeConfigFiles: string[];
  scriptFiles: string[];
  suggestedTargets: SuggestedScanTarget[];
}

export interface HostDiscoveryCandidate {
  absolutePath: string;
  displayPath: string;
  surface: SurfaceDetection;
  filesDiscovered: number;
  manifestPath: string | null;
  strongSignals: string[];
}

export interface HostDiscoveryResult {
  target: "host";
  homeDir: string;
  cwd: string;
  includeCwd: boolean;
  searchedRoots: string[];
  candidates: HostDiscoveryCandidate[];
}

interface HostSearchRootSpec {
  absolutePath: string;
  deep: number;
}

interface DiscoverHostOptions {
  homeDir?: string;
  cwd?: string;
  includeCwd?: boolean;
}

const hostDiscoveryIgnorePatterns = [
  "**/.git/**",
  "**/node_modules/**",
  "**/dist/**",
  "**/coverage/**",
  "**/.next/**",
  "**/.turbo/**",
  "**/.output/**",
  "**/.cache/**",
  "**/.npm/**",
  "**/.pnpm-store/**",
  "**/.yarn/**",
  "**/Applications/**",
  "**/Library/**",
  "**/Movies/**",
  "**/Music/**",
  "**/Pictures/**",
  "**/Public/**",
  "**/Library/Caches/**",
  "**/Library/CloudStorage/**",
  "**/.Trash/**"
];

const hostMarkerPatterns = [
  "**/traceroot.manifest.json",
  "**/traceroot.manifest.yaml",
  "**/traceroot.manifest.yml",
  "**/docker-compose*.yml",
  "**/docker-compose*.yaml",
  "**/.env",
  "**/.env.*",
  "**/*openclaw*.{json,yaml,yml,sh,bash,zsh,js,ts,py}",
  "**/*claw*.{json,yaml,yml,sh,bash,zsh,js,ts,py}",
  "**/*agent*.{json,yaml,yml,sh,bash,zsh,js,ts,py}",
  "**/*skill*.{json,yaml,yml,sh,bash,zsh,js,ts,py}",
  "**/*tool*.{json,yaml,yml,sh,bash,zsh,js,ts,py}",
  "**/*plugin*.{json,yaml,yml,sh,bash,zsh,js,ts,py}",
  "**/*mcp*.{json,yaml,yml,sh,bash,zsh,js,ts,py}",
  "**/*runtime*.{json,yaml,yml,sh,bash,zsh,js,ts,py}"
];

const skillKeywordPattern = /^(skills?|tools?|plugins?|mcp(?:-servers?)?)$/i;
const runtimeKeywordPattern = /^(runtime|config|configs|compose|deploy|infra)$/i;
const actionKeywordPattern = /(openclaw|claw|agent|skill|tool|plugin|mcp|runtime)/i;
const manifestFilePattern = /^traceroot\.manifest\.(json|ya?ml)$/i;
const dockerComposeFilePattern = /^docker-compose[^/]*\.ya?ml$/i;
const envFilePattern = /^\.env(?:\..+)?$/i;

function hostSearchRoots(
  homeDir: string,
  cwd: string,
  includeCwd: boolean
): HostSearchRootSpec[] {
  const roots = [
    { absolutePath: homeDir, deep: 4 },
    { absolutePath: path.join(homeDir, ".openclaw"), deep: 4 },
    { absolutePath: path.join(homeDir, ".mcp"), deep: 4 },
    { absolutePath: path.join(homeDir, ".config"), deep: 4 },
    { absolutePath: path.join(homeDir, "Code"), deep: 4 },
    { absolutePath: path.join(homeDir, "Projects"), deep: 4 },
    { absolutePath: path.join(homeDir, "workspace"), deep: 4 },
    { absolutePath: path.join(homeDir, "dev"), deep: 4 },
    { absolutePath: path.join(homeDir, "Documents"), deep: 3 },
    { absolutePath: path.join(homeDir, "Desktop"), deep: 3 },
    { absolutePath: path.join(homeDir, "Downloads"), deep: 3 }
  ];

  if (process.platform === "darwin") {
    roots.push({
      absolutePath: path.join(homeDir, "Library", "Application Support"),
      deep: 4
    });
  }

  if (includeCwd) {
    roots.unshift({ absolutePath: cwd, deep: 3 });
  }

  return roots;
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function canonicalPath(targetPath: string): Promise<string> {
  try {
    return await realpath(targetPath);
  } catch {
    return path.resolve(targetPath);
  }
}

function displayPathForHuman(absolutePath: string, homeDir: string): string {
  const normalizedPath = absolutePath.replace(/\\/g, "/");
  const normalizedHome = homeDir.replace(/\\/g, "/");

  if (normalizedPath === normalizedHome) {
    return "~";
  }

  if (normalizedPath.startsWith(`${normalizedHome}/`)) {
    return `~/${normalizedPath.slice(normalizedHome.length + 1)}`;
  }

  return normalizedPath;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function candidateStrength(relativePath: string): number {
  const baseName = path.basename(relativePath);

  if (manifestFilePattern.test(baseName)) {
    return 5;
  }

  if (dockerComposeFilePattern.test(baseName)) {
    return 5;
  }

  if (envFilePattern.test(baseName)) {
    return 4;
  }

  if (actionKeywordPattern.test(relativePath)) {
    return 3;
  }

  return 1;
}

function deriveCandidatePath(rootDir: string, relativePath: string): string {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  const segments = normalizedPath.split("/");
  const baseName = segments[segments.length - 1] ?? "";

  if (
    manifestFilePattern.test(baseName) ||
    dockerComposeFilePattern.test(baseName) ||
    envFilePattern.test(baseName)
  ) {
    return path.join(rootDir, path.dirname(normalizedPath));
  }

  const skillIndex = segments.findIndex((segment) => skillKeywordPattern.test(segment));
  if (skillIndex >= 0) {
    const endIndex = Math.min(segments.length - 1, skillIndex + 1);
    return path.join(rootDir, ...segments.slice(0, endIndex + 1));
  }

  const runtimeIndex = segments.findIndex((segment) => runtimeKeywordPattern.test(segment));
  if (runtimeIndex >= 0) {
    return path.join(rootDir, ...segments.slice(0, runtimeIndex + 1));
  }

  return path.join(rootDir, path.dirname(normalizedPath));
}

function summarizeStrongSignals(discovery: DiscoveryResult): string[] {
  return [
    ...discovery.manifestFiles,
    ...discovery.envFiles,
    ...discovery.runtimeConfigFiles,
    ...discovery.scriptFiles
      .filter(
        (relativePath) => pathHasActionSegment(relativePath.replace(/\//g, path.sep))
      )
      .slice(0, 3)
  ].slice(0, 5);
}

function pathHasActionSegment(absolutePath: string): boolean {
  return absolutePath
    .split(path.sep)
    .some(
      (segment) =>
        skillKeywordPattern.test(segment) ||
        runtimeKeywordPattern.test(segment) ||
        /^(openclaw|claw|agents?|mcp)$/i.test(segment)
    );
}

function isSameOrDescendant(targetPath: string, parentPath: string): boolean {
  const normalizedTarget = path.resolve(targetPath);
  const normalizedParent = path.resolve(parentPath);

  return (
    normalizedTarget === normalizedParent ||
    normalizedTarget.startsWith(`${normalizedParent}${path.sep}`)
  );
}

export async function discoverTarget(targetInput: string): Promise<DiscoveryResult> {
  const resolvedTarget = await resolveTarget(targetInput);
  const files = await discoverFiles(resolvedTarget);
  const manifestLoadResult = await loadManifest(resolvedTarget.rootDir);
  const surfaceAnalysis = analyzeSurface({
    rootDir: resolvedTarget.rootDir,
    targetPath: resolvedTarget.absolutePath,
    targetType: resolvedTarget.type,
    files,
    manifestPath: manifestLoadResult.manifestPath
  });

  return {
    target: targetInput,
    targetPath: resolvedTarget.absolutePath,
    rootDir: resolvedTarget.rootDir,
    targetType: resolvedTarget.type,
    surface: surfaceAnalysis.surface,
    manifestPath: manifestLoadResult.manifestPath,
    manifestError: manifestLoadResult.error,
    filesDiscovered: files.length,
    manifestFiles: surfaceAnalysis.manifestFiles,
    envFiles: surfaceAnalysis.envFiles,
    runtimeConfigFiles: surfaceAnalysis.runtimeConfigFiles,
    scriptFiles: surfaceAnalysis.scriptFiles,
    suggestedTargets: surfaceAnalysis.suggestedTargets
  };
}

export async function discoverHost(
  options: DiscoverHostOptions = {}
): Promise<HostDiscoveryResult> {
  const homeDir = await canonicalPath(options.homeDir ?? os.homedir());
  const cwd = await canonicalPath(options.cwd ?? process.cwd());
  const includeCwd = options.includeCwd ?? false;
  const rootSpecs = hostSearchRoots(homeDir, cwd, includeCwd);
  const searchableRoots = [];

  for (const rootSpec of rootSpecs) {
    if (await pathExists(rootSpec.absolutePath)) {
      searchableRoots.push(rootSpec);
    }
  }

  const candidateMap = new Map<
    string,
    {
      absolutePath: string;
      score: number;
    }
  >();

  for (const rootSpec of searchableRoots) {
    const relativeMatches = await fg(hostMarkerPatterns, {
      cwd: rootSpec.absolutePath,
      dot: true,
      onlyFiles: true,
      unique: true,
      deep: rootSpec.deep,
      suppressErrors: true,
      ignore: hostDiscoveryIgnorePatterns
    });

    for (const relativeMatch of relativeMatches) {
      const candidatePath = await canonicalPath(
        deriveCandidatePath(rootSpec.absolutePath, relativeMatch)
      );

      if (!includeCwd && isSameOrDescendant(candidatePath, cwd)) {
        continue;
      }

      const nextScore = candidateStrength(relativeMatch);
      const existing = candidateMap.get(candidatePath);

      if (!existing || nextScore > existing.score) {
        candidateMap.set(candidatePath, {
          absolutePath: candidatePath,
          score: nextScore
        });
      }
    }
  }

  const discoveredCandidates = [];
  const rankedCandidatePaths = [...candidateMap.values()]
    .sort((left, right) => {
      const scoreDelta = right.score - left.score;
      if (scoreDelta !== 0) {
        return scoreDelta;
      }

      return left.absolutePath.localeCompare(right.absolutePath);
    })
    .slice(0, 10);

  for (const candidate of rankedCandidatePaths) {
    try {
      const candidateStat = await stat(candidate.absolutePath);
      if (!candidateStat.isDirectory() && !candidateStat.isFile()) {
        continue;
      }
    } catch {
      continue;
    }

    try {
      const discovery = await discoverTarget(candidate.absolutePath);
      const strongSignals = summarizeStrongSignals(discovery);
      const keepCandidate =
        strongSignals.length > 0 ||
        discovery.surface.confidence === "high" ||
        pathHasActionSegment(candidate.absolutePath);

      if (!keepCandidate) {
        continue;
      }

      discoveredCandidates.push({
        absolutePath: candidate.absolutePath,
        displayPath: displayPathForHuman(candidate.absolutePath, homeDir),
        surface: discovery.surface,
        filesDiscovered: discovery.filesDiscovered,
        manifestPath: discovery.manifestPath,
        strongSignals
      });
    } catch {
      continue;
    }
  }

  return {
    target: "host",
    homeDir,
    cwd,
    includeCwd,
    searchedRoots: searchableRoots.map((rootSpec) => displayPathForHuman(rootSpec.absolutePath, homeDir)),
    candidates: discoveredCandidates
  };
}

export function hostScanCommandPath(absolutePath: string): string {
  return `traceroot-audit scan ${shellQuote(absolutePath)}`;
}
