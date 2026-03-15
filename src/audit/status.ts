import os from "node:os";
import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import type { AuditCategory, AuditEvent, AuditSeverity } from "./types";

export interface WatchStatusAttention {
  timestamp: string;
  severity: AuditSeverity;
  category: AuditCategory;
  message: string;
  action?: string;
  status?: AuditEvent["status"];
  runtime?: string;
  target?: string | null;
  channel?: string;
  sender?: string;
}

export interface WatchStatusSession {
  key: string;
  scope: "host" | "target";
  target: string | null;
  source: "doctor-watch" | "guard-watch" | "host-watch";
  startedAt: string;
  lastHeartbeatAt: string;
  lastAttention?: WatchStatusAttention;
}

interface WatchStatusFile {
  version: 1;
  updatedAt: string;
  sessions: WatchStatusSession[];
}

export function resolveWatchStatusPath(homeDir = os.homedir()): {
  dirPath: string;
  filePath: string;
} {
  const dirPath = path.join(homeDir, ".traceroot", "watch");
  return {
    dirPath,
    filePath: path.join(dirPath, "status.json")
  };
}

function sessionKey(scope: "host" | "target", target?: string | null): string {
  if (scope === "host") {
    return "host";
  }

  return `target:${path.resolve(target ?? ".")}`;
}

async function loadWatchStatusFile(homeDir = os.homedir()): Promise<WatchStatusFile> {
  const paths = resolveWatchStatusPath(homeDir);

  try {
    const raw = await readFile(paths.filePath, "utf8");
    const parsed = JSON.parse(raw) as WatchStatusFile;

    if (
      parsed &&
      parsed.version === 1 &&
      Array.isArray(parsed.sessions)
    ) {
      return parsed;
    }
  } catch {
    // fall back to empty state
  }

  return {
    version: 1,
    updatedAt: new Date().toISOString(),
    sessions: []
  };
}

async function saveWatchStatusFile(
  file: WatchStatusFile,
  homeDir = os.homedir()
): Promise<void> {
  const paths = resolveWatchStatusPath(homeDir);
  await mkdir(paths.dirPath, { recursive: true });
  await writeFile(paths.filePath, `${JSON.stringify(file, null, 2)}\n`, "utf8");
}

function attentionFromEvent(event: AuditEvent): WatchStatusAttention {
  return {
    timestamp: event.timestamp,
    severity: event.severity,
    category: event.category,
    message: event.message,
    action: event.action,
    status: event.status,
    runtime: event.runtime,
    target: event.target,
    channel: typeof event.evidence?.channel === "string" ? event.evidence.channel : undefined,
    sender: typeof event.evidence?.sender === "string" ? event.evidence.sender : undefined
  };
}

export async function updateWatchStatusSession(options: {
  scope: "host" | "target";
  source: "doctor-watch" | "guard-watch" | "host-watch";
  target?: string | null;
  heartbeatAt?: string;
  attentionEvent?: AuditEvent | null;
  homeDir?: string;
}): Promise<WatchStatusSession> {
  const homeDir = options.homeDir ?? os.homedir();
  const file = await loadWatchStatusFile(homeDir);
  const key = sessionKey(options.scope, options.target);
  const timestamp = options.heartbeatAt ?? new Date().toISOString();
  const target = options.scope === "host" ? null : path.resolve(options.target ?? ".");
  const currentIndex = file.sessions.findIndex((session) => session.key === key);
  const existing = currentIndex >= 0 ? file.sessions[currentIndex] : undefined;

  const nextSession: WatchStatusSession = {
    key,
    scope: options.scope,
    target,
    source: options.source,
    startedAt: existing?.startedAt ?? timestamp,
    lastHeartbeatAt: timestamp,
    lastAttention:
      options.attentionEvent && options.attentionEvent.severity !== "safe"
        ? attentionFromEvent(options.attentionEvent)
        : existing?.lastAttention
  };

  if (currentIndex >= 0) {
    file.sessions[currentIndex] = nextSession;
  } else {
    file.sessions.push(nextSession);
  }

  file.updatedAt = timestamp;
  file.sessions = file.sessions
    .sort((left, right) => right.lastHeartbeatAt.localeCompare(left.lastHeartbeatAt))
    .slice(0, 12);

  await saveWatchStatusFile(file, homeDir);
  return nextSession;
}

export async function loadWatchStatusSession(options: {
  scope: "host" | "target";
  target?: string | null;
  homeDir?: string;
}): Promise<WatchStatusSession | null> {
  const file = await loadWatchStatusFile(options.homeDir);
  const key = sessionKey(options.scope, options.target);

  return file.sessions.find((session) => session.key === key) ?? null;
}
