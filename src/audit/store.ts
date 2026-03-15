import os from "node:os";
import path from "node:path";
import { appendFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";

import type { AuditEvent, AuditSeverity } from "./types";

export interface AuditPaths {
  dirPath: string;
  eventsPath: string;
}

export interface ReadAuditEventsOptions {
  homeDir?: string;
  target?: string;
  severity?: AuditSeverity;
  today?: boolean;
  limit?: number;
}

export interface AuditRetentionOptions {
  maxBytes?: number;
  trimToBytes?: number;
  maxEvents?: number;
  trimToEvents?: number;
}

const DEFAULT_RETENTION: Required<AuditRetentionOptions> = {
  maxBytes: 5 * 1024 * 1024,
  trimToBytes: 4 * 1024 * 1024,
  maxEvents: 10_000,
  trimToEvents: 8_000
};

export function resolveAuditPaths(homeDir = os.homedir()): AuditPaths {
  const dirPath = path.join(homeDir, ".traceroot", "audit");
  return {
    dirPath,
    eventsPath: path.join(dirPath, "events.jsonl")
  };
}

export async function appendAuditEvents(
  events: AuditEvent[],
  homeDir = os.homedir(),
  retention: AuditRetentionOptions = {}
): Promise<AuditPaths> {
  const paths = resolveAuditPaths(homeDir);
  await mkdir(paths.dirPath, { recursive: true });

  if (events.length === 0) {
    return paths;
  }

  const content = `${events.map((event) => JSON.stringify(event)).join("\n")}\n`;
  await appendFile(paths.eventsPath, content, "utf8");
  await trimAuditEventsIfNeeded(paths.eventsPath, retention);
  return paths;
}

async function trimAuditEventsIfNeeded(
  eventsPath: string,
  retention: AuditRetentionOptions = {}
): Promise<void> {
  const policy = {
    ...DEFAULT_RETENTION,
    ...retention
  };

  let fileStats;

  try {
    fileStats = await stat(eventsPath);
  } catch {
    return;
  }

  if (fileStats.size <= policy.maxBytes) {
    return;
  }

  let content = "";

  try {
    content = await readFile(eventsPath, "utf8");
  } catch {
    return;
  }

  const lines = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length <= policy.maxEvents && fileStats.size <= policy.maxBytes) {
    return;
  }

  const keptLines: string[] = [];
  let totalBytes = 0;

  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index]!;
    const lineBytes = Buffer.byteLength(line, "utf8") + 1;

    if (
      keptLines.length >= policy.trimToEvents ||
      totalBytes + lineBytes > policy.trimToBytes
    ) {
      break;
    }

    keptLines.push(line);
    totalBytes += lineBytes;
  }

  keptLines.reverse();

  if (keptLines.length === lines.length) {
    return;
  }

  const nextContent = keptLines.length > 0 ? `${keptLines.join("\n")}\n` : "";
  await writeFile(eventsPath, nextContent, "utf8");
}

function parseAuditEvent(line: string): AuditEvent | null {
  try {
    const parsed = JSON.parse(line) as AuditEvent;
    if (
      !parsed ||
      typeof parsed !== "object" ||
      typeof parsed.timestamp !== "string" ||
      typeof parsed.severity !== "string" ||
      typeof parsed.category !== "string" ||
      typeof parsed.source !== "string" ||
      typeof parsed.message !== "string"
    ) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

function eventMatchesTarget(event: AuditEvent, target: string): boolean {
  if (!event.target) {
    return false;
  }

  return event.target === target || event.target.startsWith(`${target}${path.sep}`);
}

export async function readAuditEvents(
  options: ReadAuditEventsOptions = {}
): Promise<{
  paths: AuditPaths;
  events: AuditEvent[];
}> {
  const paths = resolveAuditPaths(options.homeDir);
  let content = "";

  try {
    content = await readFile(paths.eventsPath, "utf8");
  } catch {
    return {
      paths,
      events: []
    };
  }

  const todayLabel = new Date().toDateString();
  let events = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map(parseAuditEvent)
    .filter((event): event is AuditEvent => event !== null);

  if (options.target) {
    events = events.filter((event) => eventMatchesTarget(event, options.target!));
  }

  if (options.severity) {
    events = events.filter((event) => event.severity === options.severity);
  }

  if (options.today) {
    events = events.filter((event) => {
      const eventDate = new Date(event.timestamp);
      return !Number.isNaN(eventDate.getTime()) && eventDate.toDateString() === todayLabel;
    });
  }

  events.sort((left, right) => right.timestamp.localeCompare(left.timestamp));

  if (typeof options.limit === "number" && options.limit > 0) {
    events = events.slice(0, options.limit);
  }

  return {
    paths,
    events
  };
}
