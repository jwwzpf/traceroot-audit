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
  score: number;
  tier: "best-first" | "possible";
  categoryLabel: string;
  attention: string;
  recommendedAction: "scan" | "harden" | "doctor";
  recommendedActionLabel: string;
  recommendedCommand: string;
}

export interface HostDiscoveryResult {
  target: "host";
  homeDir: string;
  cwd: string;
  includeCwd: boolean;
  searchedRoots: string[];
  candidates: HostDiscoveryCandidate[];
}

export function hostCandidateCategoryForHuman(candidate: Pick<HostDiscoveryCandidate, "categoryLabel">): string {
  switch (candidate.categoryLabel) {
    case "OpenClaw runtime":
      return "OpenClaw 运行态";
    case "skill / tool package":
      return "Skill / Tool 动作包";
    case "MCP / tool server":
      return "MCP / 工具服务";
    case "runtime config":
      return "运行态配置";
    default:
      return "可能会驱动 AI 动作的项目";
  }
}

export function hostCandidateAttentionForHuman(
  candidate: Pick<HostDiscoveryCandidate, "categoryLabel" | "recommendedAction">
): string {
  if (candidate.categoryLabel === "OpenClaw runtime") {
    return "这里已经很像真正的运行入口，优先看一眼最容易发现暴露面和越界能力。";
  }

  if (candidate.categoryLabel === "skill / tool package") {
    return "这里定义了可复用的 agent 动作，最值得先确认它有没有超出你真正需要的权限。";
  }

  if (candidate.categoryLabel === "MCP / tool server") {
    return "这里像是 agent 会接上的工具服务，先看清它会不会把能力边界放得太宽。";
  }

  if (candidate.categoryLabel === "runtime config") {
    return "这里更像运行态配置，适合先确认有没有不必要的暴露和过宽能力。";
  }

  if (candidate.recommendedAction === "harden") {
    return "这里可能会真正驱动 AI 动作，先把边界收紧会更安心。";
  }

  return "这里可能会驱动本机上的 AI 动作，先看清它现在到底暴露了多少能力。";
}

export function hostCandidateRecommendedStepForHuman(
  candidate: Pick<HostDiscoveryCandidate, "recommendedAction" | "categoryLabel">
): string {
  if (candidate.recommendedAction === "doctor") {
    if (candidate.categoryLabel === "OpenClaw runtime") {
      return "直接让 TraceRoot Doctor 带你检查并守住这个运行态";
    }

    if (candidate.categoryLabel === "MCP / tool server") {
      return "直接让 TraceRoot Doctor 带你检查这个工具服务的边界";
    }

    return "直接让 TraceRoot Doctor 带你把这里先看清楚、再收紧";
  }

  if (candidate.recommendedAction === "harden") {
    if (candidate.categoryLabel === "OpenClaw runtime") {
      return "先让 TraceRoot 帮你把这个运行态收紧一遍";
    }

    if (candidate.categoryLabel === "MCP / tool server") {
      return "先让 TraceRoot 帮你把这个工具服务的边界收紧";
    }

    return "先让 TraceRoot 帮你把这里的动作边界收紧";
  }

  return "先让 TraceRoot 看清这里当前暴露出了多少风险面";
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
const openClawPathPattern = /(^|\/)(?:\.openclaw|openclaw|claw)(\/|$)/i;
const mcpPathPattern = /(^|\/)(?:\.mcp|mcp(?:-servers?)?)(\/|$)|\.mcp\.(json|ya?ml)$/i;
const skillPathLikePattern = /(^|\/)(?:skills?|tools?|plugins?)(\/|$)/i;
const genericAppPathPattern = /(^|\/)(?:frontend|backend|mobile|apps?|web)(\/|$)/i;

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

function hostDoctorCommandPath(absolutePath: string): string {
  return `traceroot-audit doctor ${shellQuote(absolutePath)}`;
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

function candidateMetadata(
  discovery: DiscoveryResult,
  candidatePath: string
): Pick<
  HostDiscoveryCandidate,
  | "score"
  | "tier"
  | "categoryLabel"
  | "attention"
  | "recommendedAction"
  | "recommendedActionLabel"
  | "recommendedCommand"
> {
  const normalizedCandidatePath = candidatePath.replace(/\\/g, "/");
  const normalizedSignals = [
    ...discovery.manifestFiles,
    ...discovery.envFiles,
    ...discovery.runtimeConfigFiles,
    ...discovery.scriptFiles
  ].map((value) => value.replace(/\\/g, "/"));

  const hasManifest = discovery.manifestFiles.length > 0;
  const hasDockerCompose = discovery.runtimeConfigFiles.some((relativePath) =>
    dockerComposeFilePattern.test(path.basename(relativePath))
  );
  const hasEnv = discovery.envFiles.length > 0;
  const hasOpenClawMarker =
    openClawPathPattern.test(normalizedCandidatePath) ||
    normalizedSignals.some((value) => openClawPathPattern.test(value));
  const hasMcpMarker =
    mcpPathPattern.test(normalizedCandidatePath) ||
    normalizedSignals.some((value) => mcpPathPattern.test(value));
  const hasSkillMarker =
    skillPathLikePattern.test(normalizedCandidatePath) ||
    normalizedSignals.some((value) => skillPathLikePattern.test(value));
  const hasActionMarker =
    pathHasActionSegment(candidatePath) ||
    normalizedSignals.some((value) => actionKeywordPattern.test(value));
  const looksGenericApp =
    genericAppPathPattern.test(normalizedCandidatePath) &&
    !hasOpenClawMarker &&
    !hasMcpMarker &&
    !hasSkillMarker &&
    !hasManifest;

  let score = 0;

  if (hasOpenClawMarker) {
    score += 24;
  }

  if (hasMcpMarker) {
    score += 20;
  }

  if (hasManifest) {
    score += 18;
  }

  if (hasSkillMarker) {
    score += 14;
  }

  if (hasDockerCompose) {
    score += 12;
  }

  if (hasEnv) {
    score += 6;
  }

  if (hasActionMarker) {
    score += 6;
  }

  if (discovery.surface.confidence === "high") {
    score += 4;
  } else if (discovery.surface.confidence === "medium") {
    score += 2;
  }

  if (looksGenericApp) {
    score -= 8;
  }

  let categoryLabel = "possible agent-capable project";
  let attention = "worth checking if this project actually drives AI actions on your machine";
  let recommendedAction: HostDiscoveryCandidate["recommendedAction"] = "scan";
  let recommendedActionLabel = "scan this surface first";
  let recommendedCommand = hostScanCommandPath(candidatePath);

  if (hasOpenClawMarker && hasDockerCompose) {
    categoryLabel = "OpenClaw runtime";
    attention = "worth checking first: runtime wiring and exposure signals were found";
    recommendedAction = "doctor";
    recommendedActionLabel = "open TraceRoot Doctor here first";
    recommendedCommand = hostDoctorCommandPath(candidatePath);
  } else if (hasManifest || hasSkillMarker) {
    categoryLabel = "skill / tool package";
    attention = "worth checking first: explicit reusable agent actions were detected";
    recommendedAction = "doctor";
    recommendedActionLabel = "open TraceRoot Doctor here first";
    recommendedCommand = hostDoctorCommandPath(candidatePath);
  } else if (hasMcpMarker) {
    categoryLabel = "MCP / tool server";
    attention = "worth checking first: MCP or tool-server wiring was detected";
    recommendedAction = "doctor";
    recommendedActionLabel = "open TraceRoot Doctor here first";
    recommendedCommand = hostDoctorCommandPath(candidatePath);
  } else if (hasDockerCompose || hasEnv) {
    categoryLabel = "runtime config";
    attention = "worth checking if this runtime is broader or more exposed than you intended";
    recommendedAction = "doctor";
    recommendedActionLabel = "open TraceRoot Doctor here first";
    recommendedCommand = hostDoctorCommandPath(candidatePath);
  }

  const tier = score >= 24 ? "best-first" : "possible";

  return {
    score,
    tier,
    categoryLabel,
    attention,
    recommendedAction,
    recommendedActionLabel,
    recommendedCommand
  };
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

      const metadata = candidateMetadata(discovery, candidate.absolutePath);

      discoveredCandidates.push({
        absolutePath: candidate.absolutePath,
        displayPath: displayPathForHuman(candidate.absolutePath, homeDir),
        surface: discovery.surface,
        filesDiscovered: discovery.filesDiscovered,
        manifestPath: discovery.manifestPath,
        strongSignals,
        score: metadata.score,
        tier: metadata.tier,
        categoryLabel: metadata.categoryLabel,
        attention: metadata.attention,
        recommendedAction: metadata.recommendedAction,
        recommendedActionLabel: metadata.recommendedActionLabel,
        recommendedCommand: metadata.recommendedCommand
      });
    } catch {
      continue;
    }
  }

  discoveredCandidates.sort((left, right) => {
    if (left.tier !== right.tier) {
      return left.tier === "best-first" ? -1 : 1;
    }

    const scoreDelta = right.score - left.score;
    if (scoreDelta !== 0) {
      return scoreDelta;
    }

    return left.absolutePath.localeCompare(right.absolutePath);
  });

  const dedupedCandidates = [];

  for (const candidate of discoveredCandidates) {
    const hasKeptAncestor = dedupedCandidates.some((keptCandidate) =>
      isSameOrDescendant(candidate.absolutePath, keptCandidate.absolutePath)
    );

    if (hasKeptAncestor) {
      continue;
    }

    dedupedCandidates.push(candidate);
  }

  return {
    target: "host",
    homeDir,
    cwd,
    includeCwd,
    searchedRoots: searchableRoots.map((rootSpec) => displayPathForHuman(rootSpec.absolutePath, homeDir)),
    candidates: dedupedCandidates.slice(0, 8)
  };
}

export function hostScanCommandPath(absolutePath: string): string {
  return `traceroot-audit scan ${shellQuote(absolutePath)}`;
}
