import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export interface SavedAuditCoverageSnapshot {
  version: 1;
  updatedAt: string;
  coveredActions: string[];
  pendingActions: string[];
  installedEntrypointCount: number;
  installedEntrypointLabels: string[];
}

export function resolveAuditCoveragePath(rootDir: string): string {
  return path.join(rootDir, ".traceroot", "audit-coverage.json");
}

export async function saveAuditCoverageSnapshot(
  rootDir: string,
  snapshot: SavedAuditCoverageSnapshot
): Promise<string> {
  const outputPath = resolveAuditCoveragePath(rootDir);
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
  return outputPath;
}

export async function loadAuditCoverageSnapshot(rootDir: string): Promise<{
  path: string;
  snapshot: SavedAuditCoverageSnapshot | null;
  error?: string;
}> {
  const coveragePath = resolveAuditCoveragePath(rootDir);

  try {
    const raw = await readFile(coveragePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<SavedAuditCoverageSnapshot>;

    if (
      parsed.version !== 1 ||
      !Array.isArray(parsed.coveredActions) ||
      !Array.isArray(parsed.pendingActions) ||
      typeof parsed.installedEntrypointCount !== "number" ||
      !Array.isArray(parsed.installedEntrypointLabels)
    ) {
      return {
        path: coveragePath,
        snapshot: null,
        error: "invalid-shape"
      };
    }

    return {
      path: coveragePath,
      snapshot: {
        version: 1,
        updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date(0).toISOString(),
        coveredActions: parsed.coveredActions.map(String),
        pendingActions: parsed.pendingActions.map(String),
        installedEntrypointCount: parsed.installedEntrypointCount,
        installedEntrypointLabels: parsed.installedEntrypointLabels.map(String)
      }
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        path: coveragePath,
        snapshot: null
      };
    }

    return {
      path: coveragePath,
      snapshot: null,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}
