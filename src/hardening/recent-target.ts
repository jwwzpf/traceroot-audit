import os from "node:os";
import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import { displayUserPath } from "../utils/paths";

interface RecentDoctorTarget {
  version: 1;
  updatedAt: string;
  targetPath: string;
}

function recentTargetPath(): string {
  return path.join(os.homedir(), ".traceroot", "doctor-recent.json");
}

export async function loadRecentDoctorTarget(): Promise<string | null> {
  try {
    const raw = await readFile(recentTargetPath(), "utf8");
    const parsed = JSON.parse(raw) as RecentDoctorTarget;
    if (parsed?.version !== 1 || typeof parsed.targetPath !== "string" || parsed.targetPath.length === 0) {
      return null;
    }

    return parsed.targetPath;
  } catch {
    return null;
  }
}

export async function saveRecentDoctorTarget(targetPath: string): Promise<void> {
  const filePath = recentTargetPath();
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(
    filePath,
    `${JSON.stringify(
      {
        version: 1,
        updatedAt: new Date().toISOString(),
        targetPath
      } satisfies RecentDoctorTarget,
      null,
      2
    )}\n`,
    "utf8"
  );
}

export function recentTargetLabel(targetPath: string): string {
  return displayUserPath(targetPath);
}
