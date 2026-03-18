import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import { resolveStateHomeDir } from "../utils/home";

type ReviewScope = "host" | "target";

interface ReviewStateEntry {
  key: string;
  scope: ReviewScope;
  target: string | null;
  lastReviewedAt: string;
}

interface ReviewStateFile {
  version: 1;
  updatedAt: string;
  entries: ReviewStateEntry[];
}

function reviewStatePath(homeDir = resolveStateHomeDir()): string {
  return path.join(homeDir, ".traceroot", "audit", "review-state.json");
}

function reviewKey(scope: ReviewScope, target?: string | null): string {
  if (scope === "host") {
    return "host";
  }

  return `target:${path.resolve(target ?? ".")}`;
}

async function loadReviewStateFile(
  homeDir = resolveStateHomeDir()
): Promise<ReviewStateFile> {
  try {
    const raw = await readFile(reviewStatePath(homeDir), "utf8");
    const parsed = JSON.parse(raw) as ReviewStateFile;

    if (parsed && parsed.version === 1 && Array.isArray(parsed.entries)) {
      return parsed;
    }
  } catch {
    // ignore and fall through
  }

  return {
    version: 1,
    updatedAt: new Date().toISOString(),
    entries: []
  };
}

async function saveReviewStateFile(
  file: ReviewStateFile,
  homeDir = resolveStateHomeDir()
): Promise<void> {
  const filePath = reviewStatePath(homeDir);
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(file, null, 2)}\n`, "utf8");
}

export async function loadAuditReviewState(options: {
  scope: ReviewScope;
  target?: string | null;
  homeDir?: string;
}): Promise<ReviewStateEntry | null> {
  const file = await loadReviewStateFile(options.homeDir);
  const key = reviewKey(options.scope, options.target);

  return file.entries.find((entry) => entry.key === key) ?? null;
}

export async function saveAuditReviewState(options: {
  scope: ReviewScope;
  target?: string | null;
  reviewedAt?: string;
  homeDir?: string;
}): Promise<void> {
  const homeDir = options.homeDir ?? resolveStateHomeDir();
  const file = await loadReviewStateFile(homeDir);
  const key = reviewKey(options.scope, options.target);
  const reviewedAt = options.reviewedAt ?? new Date().toISOString();
  const target = options.scope === "host" ? null : path.resolve(options.target ?? ".");
  const nextEntry: ReviewStateEntry = {
    key,
    scope: options.scope,
    target,
    lastReviewedAt: reviewedAt
  };

  const existingIndex = file.entries.findIndex((entry) => entry.key === key);
  if (existingIndex >= 0) {
    file.entries[existingIndex] = nextEntry;
  } else {
    file.entries.push(nextEntry);
  }

  file.updatedAt = reviewedAt;
  file.entries = file.entries
    .sort((left, right) => right.lastReviewedAt.localeCompare(left.lastReviewedAt))
    .slice(0, 16);

  await saveReviewStateFile(file, homeDir);
}
