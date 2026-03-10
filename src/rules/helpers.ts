import path from "node:path";

import { findLineMatches, truncateEvidence, type LineMatch } from "../utils/text";

import type { ScannableFile } from "./types";

export interface SignalMatch {
  file: string;
  line: number;
  evidence: string;
}

const manifestFileNames = new Set([
  "traceroot.manifest.json",
  "traceroot.manifest.yaml",
  "traceroot.manifest.yml"
]);

const configExtensions = new Set([".json", ".yaml", ".yml"]);
const executableExtensions = new Set([".sh", ".bash", ".zsh", ".js", ".ts", ".py"]);

export const destructivePatterns = [
  /\brm\s+-rf\b/i,
  /\bdelete\b/i,
  /\bremove\b/i,
  /\barchive\b/i,
  /\bpurchase\b/i,
  /\border\b/i,
  /\bsend[_ -]?email\b/i,
  /\bbulk[_ -]?(?:modify|update|delete|remove)\b/i
] as const;

export const safeguardPatterns = [
  /\bconfirm(?:ation)?\b/i,
  /\bapproval(?:_required)?\b/i,
  /\bdry[_ -]?run\b/i,
  /\bare you sure\b/i,
  /\bprompt\b/i,
  /\bsafeguard/i
] as const;

export const longRunningPatterns = [
  /\bwhile\s+true\b/i,
  /\bsetInterval\s*\(/,
  /\bwatch\s*\(/i,
  /\blisten\s*\(/i,
  /\bdaemon\b/i,
  /\bworker\b/i,
  /\bserve\b/i
] as const;

export function isManifestFile(file: ScannableFile): boolean {
  return manifestFileNames.has(file.relativePath);
}

export function isConfigLikeFile(file: ScannableFile): boolean {
  if (file.relativePath === ".env" || file.relativePath.startsWith(".env.")) {
    return true;
  }

  const baseName = path.basename(file.relativePath).toLowerCase();
  return baseName.startsWith("docker-compose") || configExtensions.has(file.extension);
}

export function isExecutableTextFile(file: ScannableFile): boolean {
  return executableExtensions.has(file.extension);
}

export function firstSignalInFile(
  file: ScannableFile,
  patterns: readonly RegExp[]
): SignalMatch | null {
  for (const pattern of patterns) {
    const match = findLineMatches(file.content, pattern)[0];
    if (match) {
      return toSignalMatch(file, match);
    }
  }

  return null;
}

export function allSignalsInFile(
  file: ScannableFile,
  patterns: readonly RegExp[]
): SignalMatch[] {
  const signals: SignalMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of patterns) {
    const matches = findLineMatches(file.content, pattern);
    for (const match of matches) {
      const key = `${match.line}:${match.text}`;
      if (seen.has(key)) {
        continue;
      }

      seen.add(key);
      signals.push(toSignalMatch(file, match));
    }
  }

  return signals;
}

function toSignalMatch(file: ScannableFile, match: LineMatch): SignalMatch {
  return {
    file: file.relativePath,
    line: match.line,
    evidence: truncateEvidence(match.text)
  };
}
