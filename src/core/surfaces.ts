import path from "node:path";

import type { ScannableFile, ScanTargetType } from "../rules/types";

export type ScanSurfaceKind = "project" | "skill" | "runtime";
export type SurfaceConfidence = "high" | "medium" | "low";

export interface SurfaceDetection {
  kind: ScanSurfaceKind;
  confidence: SurfaceConfidence;
  reasons: string[];
}

export interface SuggestedScanTarget {
  displayPath: string;
  absolutePath: string;
  kind: ScanSurfaceKind;
  reason: string;
}

export interface SurfaceAnalysis {
  surface: SurfaceDetection;
  manifestFiles: string[];
  envFiles: string[];
  runtimeConfigFiles: string[];
  scriptFiles: string[];
  suggestedTargets: SuggestedScanTarget[];
}

interface SurfaceAnalysisInput {
  rootDir: string;
  targetPath: string;
  targetType: ScanTargetType;
  files: ScannableFile[];
  manifestPath: string | null;
}

const scriptExtensions = new Set([".sh", ".bash", ".zsh", ".js", ".ts", ".py"]);
const skillPathPattern =
  /(^|\/)(skills?|tools?|plugins?|mcp(?:-servers?)?|agents?)(\/|$)/i;
const runtimePathPattern =
  /(^|\/)(runtime|config|configs|compose|docker|deploy|infra)(\/|$)/i;
const dockerComposePattern = /(^|\/)docker-compose[^/]*\.ya?ml$/i;
const configLikePattern =
  /(^|\/)(?:[^/]*?(?:runtime|compose|docker|openclaw|claw|agent|mcp)[^/]*)\.(json|ya?ml)$/i;
const ignoredRuntimeConfigPattern =
  /(^|\/)(?:tsconfig(?:\.[^/]+)?|jsconfig|eslint\.config|prettier\.config|vitest\.config|vite\.config|jest\.config|babel\.config|webpack\.config|tailwind\.config|postcss\.config|metro\.config|next\.config|nuxt\.config|astro\.config|svelte\.config)\.[^/]+$/i;

function normalizeSuggestionPath(relativePath: string): string {
  if (relativePath === "." || relativePath.length === 0) {
    return ".";
  }

  return relativePath.replace(/\\/g, "/");
}

function collectManifestFiles(
  rootDir: string,
  files: ScannableFile[],
  manifestPath: string | null
): string[] {
  const discoveredManifests = files
    .filter((file) => path.basename(file.relativePath).startsWith("traceroot.manifest."))
    .map((file) => file.relativePath);

  if (!manifestPath) {
    return [...new Set(discoveredManifests)];
  }

  const relativeManifestPath = path.isAbsolute(manifestPath)
    ? path.relative(rootDir, manifestPath).replace(/\\/g, "/") || "."
    : manifestPath.replace(/\\/g, "/");

  return [...new Set([...discoveredManifests, relativeManifestPath])].sort((left, right) =>
    left.localeCompare(right)
  );
}

function collectEnvFiles(files: ScannableFile[]): string[] {
  return files
    .filter((file) => path.basename(file.relativePath).startsWith(".env"))
    .map((file) => file.relativePath)
    .sort((left, right) => left.localeCompare(right));
}

function collectRuntimeConfigFiles(files: ScannableFile[]): string[] {
  return files
    .filter(
      (file) =>
        !ignoredRuntimeConfigPattern.test(file.relativePath) &&
        (dockerComposePattern.test(file.relativePath) || configLikePattern.test(file.relativePath))
    )
    .map((file) => file.relativePath)
    .sort((left, right) => left.localeCompare(right));
}

function collectScriptFiles(files: ScannableFile[]): string[] {
  return files
    .filter((file) => scriptExtensions.has(file.extension))
    .map((file) => file.relativePath)
    .sort((left, right) => left.localeCompare(right));
}

function surfaceLabelScoreOrder(kind: ScanSurfaceKind): number {
  if (kind === "skill") {
    return 0;
  }

  if (kind === "runtime") {
    return 1;
  }

  return 2;
}

export function surfaceLabel(kind: ScanSurfaceKind): string {
  if (kind === "skill") {
    return "skill / tool package";
  }

  if (kind === "runtime") {
    return "runtime config";
  }

  return "agent project";
}

export function analyzeSurface(input: SurfaceAnalysisInput): SurfaceAnalysis {
  const manifestFiles = collectManifestFiles(input.rootDir, input.files, input.manifestPath);
  const envFiles = collectEnvFiles(input.files);
  const runtimeConfigFiles = collectRuntimeConfigFiles(input.files);
  const scriptFiles = collectScriptFiles(input.files);

  const scores: Record<ScanSurfaceKind, number> = {
    project: 0,
    skill: 0,
    runtime: 0
  };
  const reasons: Record<ScanSurfaceKind, string[]> = {
    project: [],
    skill: [],
    runtime: []
  };
  const targetPathLower = input.targetPath.toLowerCase();

  if (manifestFiles.length > 0) {
    scores.skill += 4;
    reasons.skill.push("found TraceRoot manifest metadata");
  }

  if (skillPathPattern.test(targetPathLower)) {
    scores.skill += 3;
    reasons.skill.push('target path looks like a "skill", "tool", or "plugin" package');
  }

  if (scriptFiles.length > 0 && (manifestFiles.length > 0 || skillPathPattern.test(targetPathLower))) {
    scores.skill += 1;
    reasons.skill.push("contains executable files that define reusable agent actions");
  }

  if (envFiles.length > 0) {
    scores.runtime += 3;
    reasons.runtime.push("found environment files that can shape a local runtime");
  }

  if (runtimeConfigFiles.some((relativePath) => dockerComposePattern.test(relativePath))) {
    scores.runtime += 5;
    reasons.runtime.push("found docker-compose runtime exposure or wiring files");
  }

  if (
    runtimeConfigFiles.length > 0 &&
    !runtimeConfigFiles.some((relativePath) => dockerComposePattern.test(relativePath))
  ) {
    scores.runtime += 2;
    reasons.runtime.push("found config files that likely define runtime behavior");
  }

  if (runtimePathPattern.test(targetPathLower)) {
    scores.runtime += 2;
    reasons.runtime.push('target path looks like a "runtime" or "config" surface');
  }

  if (scriptFiles.some((relativePath) => runtimePathPattern.test(relativePath))) {
    scores.runtime += 1;
    reasons.runtime.push("contains helper scripts under a runtime/config path");
  }

  if (scriptFiles.length > 0) {
    scores.project += 2;
    reasons.project.push("contains executable files that can become agent actions");
  }

  if (scriptFiles.length >= 3) {
    scores.project += 1;
    reasons.project.push("contains multiple action-capable source files");
  }

  if (scriptFiles.length > 0 && (envFiles.length > 0 || runtimeConfigFiles.length > 0)) {
    scores.project += 2;
    reasons.project.push("mixes executable code with runtime/config wiring");
  }

  if (input.targetType === "file" && scriptFiles.length === 1) {
    scores.project += 1;
    reasons.project.push("single file target looks like a runnable automation script");
  }

  const rankedKinds = (Object.keys(scores) as ScanSurfaceKind[]).sort((left, right) => {
    const scoreDelta = scores[right] - scores[left];
    if (scoreDelta !== 0) {
      return scoreDelta;
    }

    return surfaceLabelScoreOrder(left) - surfaceLabelScoreOrder(right);
  });
  const primaryKind = rankedKinds[0] ?? "project";
  const primaryScore = scores[primaryKind];
  const confidence: SurfaceConfidence =
    primaryScore >= 6 ? "high" : primaryScore >= 3 ? "medium" : "low";
  const primaryReasons =
    reasons[primaryKind].length > 0
      ? reasons[primaryKind]
      : ["found only a small amount of scanable material, so this is a best-effort guess"];

  const suggestionMap = new Map<string, SuggestedScanTarget>();
  const addSuggestion = (
    displayPath: string,
    kind: ScanSurfaceKind,
    reason: string,
    absolutePath = displayPath === "." ? input.rootDir : path.join(input.rootDir, displayPath)
  ) => {
    const normalizedPath = normalizeSuggestionPath(displayPath);
    const key = `${kind}:${normalizedPath}`;

    if (!suggestionMap.has(key)) {
      suggestionMap.set(key, {
        displayPath: normalizedPath,
        absolutePath,
        kind,
        reason
      });
    }
  };

  addSuggestion(".", primaryKind, primaryReasons[0]);

  for (const manifestFile of manifestFiles) {
    const manifestDir = path.dirname(manifestFile);
    addSuggestion(
      manifestDir === "." ? "." : manifestDir,
      "skill",
      "contains TraceRoot manifest metadata"
    );
  }

  for (const runtimeFile of [...envFiles, ...runtimeConfigFiles]) {
    const runtimeDir = path.dirname(runtimeFile);
    addSuggestion(
      runtimeDir === "." ? "." : runtimeDir,
      "runtime",
      "contains runtime wiring or environment files"
    );
  }

  for (const scriptFile of scriptFiles) {
    const segments = scriptFile.split("/");
    const firstSegment = segments[0];

    if (skillPathPattern.test(firstSegment)) {
      addSuggestion(firstSegment, "skill", 'directory name suggests a "skill" or "tool" package');
    }

    if (runtimePathPattern.test(firstSegment)) {
      addSuggestion(firstSegment, "runtime", 'directory name suggests a runtime/config surface');
    }
  }

  return {
    surface: {
      kind: primaryKind,
      confidence,
      reasons: primaryReasons
    },
    manifestFiles,
    envFiles,
    runtimeConfigFiles,
    scriptFiles,
    suggestedTargets: [...suggestionMap.values()].slice(0, 6)
  };
}
