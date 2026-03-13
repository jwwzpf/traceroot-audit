import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export interface StoredWatchPreferences {
  version: 1;
  updatedAt: string;
  notifications: {
    webhookUrl?: string;
    openclawChannel?: string;
    openclawTarget?: string;
    openclawAccount?: string;
  };
}

function preferencesPath(rootDir: string): string {
  return path.join(rootDir, ".traceroot", "doctor-watch.json");
}

export async function loadWatchPreferences(
  rootDir: string
): Promise<StoredWatchPreferences | null> {
  try {
    const raw = await readFile(preferencesPath(rootDir), "utf8");
    const parsed = JSON.parse(raw) as StoredWatchPreferences;
    if (parsed?.version !== 1 || typeof parsed.notifications !== "object") {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

export async function saveWatchPreferences(
  rootDir: string,
  preferences: StoredWatchPreferences
): Promise<void> {
  const filePath = preferencesPath(rootDir);
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(preferences, null, 2)}\n`, "utf8");
}
