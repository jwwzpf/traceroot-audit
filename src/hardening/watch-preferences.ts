import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { resolveStateHomeDir } from "../utils/home";

export interface StoredWatchPreferences {
  version: 1;
  updatedAt: string;
  mode: "local-only" | "webhook" | "channel";
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

function machinePreferencesPath(): string {
  return path.join(resolveStateHomeDir(), ".traceroot", "doctor-watch-host.json");
}

export async function loadWatchPreferences(
  rootDir: string
): Promise<StoredWatchPreferences | null> {
  try {
    const raw = await readFile(preferencesPath(rootDir), "utf8");
    const parsed = JSON.parse(raw) as
      | StoredWatchPreferences
      | (Omit<StoredWatchPreferences, "mode"> & { mode?: unknown });
    if (parsed?.version !== 1 || typeof parsed.notifications !== "object") {
      return null;
    }

    const inferredMode =
      parsed.mode === "local-only" ||
      parsed.mode === "webhook" ||
      parsed.mode === "channel"
        ? parsed.mode
        : parsed.notifications.webhookUrl
          ? "webhook"
          : parsed.notifications.openclawChannel && parsed.notifications.openclawTarget
            ? "channel"
            : null;

    if (!inferredMode) {
      return null;
    }

    return {
      ...parsed,
      mode: inferredMode
    };
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

export async function loadMachineWatchPreferences(): Promise<StoredWatchPreferences | null> {
  try {
    const raw = await readFile(machinePreferencesPath(), "utf8");
    const parsed = JSON.parse(raw) as
      | StoredWatchPreferences
      | (Omit<StoredWatchPreferences, "mode"> & { mode?: unknown });
    if (parsed?.version !== 1 || typeof parsed.notifications !== "object") {
      return null;
    }

    const inferredMode =
      parsed.mode === "local-only" ||
      parsed.mode === "webhook" ||
      parsed.mode === "channel"
        ? parsed.mode
        : parsed.notifications.webhookUrl
          ? "webhook"
          : parsed.notifications.openclawChannel && parsed.notifications.openclawTarget
            ? "channel"
            : null;

    if (!inferredMode) {
      return null;
    }

    return {
      ...parsed,
      mode: inferredMode
    };
  } catch {
    return null;
  }
}

export async function saveMachineWatchPreferences(
  preferences: StoredWatchPreferences
): Promise<void> {
  const filePath = machinePreferencesPath();
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(preferences, null, 2)}\n`, "utf8");
}
