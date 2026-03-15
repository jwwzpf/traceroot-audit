import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import { resolveStateHomeDir } from "../utils/home";
import { displayUserPath } from "../utils/paths";

interface RecentDoctorTarget {
  version: 1;
  updatedAt: string;
  targetPath: string;
}

interface RecentDoctorContext {
  version: 2;
  updatedAt: string;
  scope: "target" | "host";
  targetPath?: string;
}

function recentTargetPath(): string {
  return path.join(resolveStateHomeDir(), ".traceroot", "doctor-recent.json");
}

export async function loadRecentDoctorTarget(): Promise<string | null> {
  const context = await loadRecentDoctorContext();
  if (!context || context.scope !== "target" || !context.targetPath) {
    return null;
  }

  return context.targetPath;
}

export async function loadRecentDoctorContext(): Promise<
  | {
      scope: "target";
      updatedAt: string;
      targetPath: string;
    }
  | {
      scope: "host";
      updatedAt: string;
    }
  | null
> {
  try {
    const raw = await readFile(recentTargetPath(), "utf8");
    const parsed = JSON.parse(raw) as RecentDoctorTarget | RecentDoctorContext;

    if (parsed && typeof parsed === "object" && "version" in parsed) {
      if (parsed.version === 2 && "scope" in parsed) {
        if (parsed.scope === "host") {
          return {
            scope: "host",
            updatedAt: parsed.updatedAt
          };
        }

        if (
          parsed.scope === "target" &&
          typeof parsed.targetPath === "string" &&
          parsed.targetPath.length > 0
        ) {
          return {
            scope: "target",
            updatedAt: parsed.updatedAt,
            targetPath: parsed.targetPath
          };
        }

        return null;
      }

      if (
        parsed.version === 1 &&
        "targetPath" in parsed &&
        typeof parsed.targetPath === "string" &&
        parsed.targetPath.length > 0
      ) {
        return {
          scope: "target",
          updatedAt: parsed.updatedAt,
          targetPath: parsed.targetPath
        };
      }
    }
  } catch {
    // ignore and fall through
  }

  return null;
}

export async function saveRecentDoctorTarget(targetPath: string): Promise<void> {
  const filePath = recentTargetPath();
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(
    filePath,
    `${JSON.stringify(
      {
        version: 2,
        updatedAt: new Date().toISOString(),
        scope: "target",
        targetPath
      } satisfies RecentDoctorContext,
      null,
      2
    )}\n`,
    "utf8"
  );
}

export async function saveRecentDoctorHostScope(): Promise<void> {
  const filePath = recentTargetPath();
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(
    filePath,
    `${JSON.stringify(
      {
        version: 2,
        updatedAt: new Date().toISOString(),
        scope: "host"
      } satisfies RecentDoctorContext,
      null,
      2
    )}\n`,
    "utf8"
  );
}

export function recentTargetLabel(targetPath: string): string {
  return displayUserPath(targetPath);
}
