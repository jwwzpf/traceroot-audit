import path from "node:path";
import { readFile } from "node:fs/promises";

import fg from "fast-glob";

import type { AuditEvent, AuditSeverity } from "./types";
import { actionLabel } from "./presentation";
import { displayUserPath } from "../utils/paths";

export interface RuntimeEventFeed {
  absolutePath: string;
  displayPath: string;
}

export interface RuntimeFeedCursor {
  lineCounts: Map<string, number>;
}

const candidateRelativePaths = [
  ".traceroot/runtime-events.jsonl",
  "runtime-events.jsonl",
  "openclaw-events.jsonl",
  "mcp-events.jsonl",
  "agent-events.jsonl",
  "action-events.jsonl",
  path.join("logs", "runtime-events.jsonl"),
  path.join("logs", "openclaw-events.jsonl"),
  path.join("logs", "mcp-events.jsonl"),
  path.join("logs", "agent-events.jsonl"),
  path.join("logs", "action-events.jsonl"),
  path.join(".openclaw", "events.jsonl"),
  path.join(".mcp", "events.jsonl")
];

const candidateGlobPatterns = [
  "logs/**/*events*.jsonl",
  "logs/**/*actions*.jsonl",
  ".openclaw/**/*events*.jsonl",
  ".openclaw/**/*actions*.jsonl",
  ".mcp/**/*events*.jsonl",
  ".mcp/**/*actions*.jsonl"
];

function normalizeSeverity(value?: unknown): AuditSeverity | undefined {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (!normalized) {
    return undefined;
  }

  if (["critical", "crit", "severe"].includes(normalized)) {
    return "critical";
  }

  if (["high-risk", "high", "danger", "warning-high"].includes(normalized)) {
    return "high-risk";
  }

  if (["risky", "risk", "warning", "medium"].includes(normalized)) {
    return "risky";
  }

  return undefined;
}

function severityFromAction(action?: string): AuditSeverity {
  const normalized = (action ?? "").toLowerCase();

  if (/(purchase|payment|checkout|order|bank|wallet|trade|broker|finance)/.test(normalized)) {
    return "critical";
  }

  if (/(send-email|publish|post|message|delete|remove|secret|sensitive)/.test(normalized)) {
    return "high-risk";
  }

  if (normalized.length > 0) {
    return "risky";
  }

  return "safe";
}

function normalizeStatus(value?: unknown): AuditEvent["status"] {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (["attempted", "attempt", "started", "start", "running"].includes(normalized)) {
    return "attempted";
  }

  if (["succeeded", "success", "completed", "done", "ok"].includes(normalized)) {
    return "succeeded";
  }

  if (["failed", "failure", "error"].includes(normalized)) {
    return "failed";
  }

  return "attempted";
}

function getNestedValue(
  source: Record<string, unknown>,
  pathSegments: string[]
): unknown {
  let current: unknown = source;

  for (const segment of pathSegments) {
    if (!current || typeof current !== "object") {
      return undefined;
    }

    current = (current as Record<string, unknown>)[segment];
  }

  return current;
}

function pickString(
  source: Record<string, unknown>,
  candidates: Array<string | string[]>
): string | undefined {
  for (const candidate of candidates) {
    const value = Array.isArray(candidate)
      ? getNestedValue(source, candidate)
      : source[candidate];

    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }

  return undefined;
}

function inferRecommendation(action?: string, severity?: AuditSeverity): string | undefined {
  const normalized = (action ?? "").toLowerCase();

  if (normalized === "send-email") {
    return "先确认这封邮件是不是真的该发出去。";
  }

  if (/(publish|post|message)/.test(normalized)) {
    return "先确认这条对外消息是不是真的该发出去。";
  }

  if (/(delete|remove)/.test(normalized)) {
    return "先确认这次删改文件是不是你真的想让 agent 去做。";
  }

  if (/(payment|purchase|checkout|order)/.test(normalized)) {
    return "这类涉及付款或下单的动作，最好始终先让人拍板。";
  }

  if (severity === "critical" || severity === "high-risk") {
    return "先确认这个高风险动作是不是你真的想让 agent 去做。";
  }

  return undefined;
}

function inferMessage(action: string | undefined, status: AuditEvent["status"], runtimeName?: string): string {
  const label = actionLabel(action);
  const actor = runtimeName ? `${runtimeName}` : "运行时";

  if (status === "succeeded") {
    return `${actor} 报告这个动作已经完成：${label}。`;
  }

  if (status === "failed") {
    return `${actor} 报告这个动作没有成功：${label}。`;
  }

  return `${actor} 刚刚报告了一个动作：${label}。`;
}

function parseRuntimeFeedEvent(line: string, targetRoot: string): AuditEvent | null {
  let parsed: Record<string, unknown> | unknown[];

  try {
    parsed = JSON.parse(line) as Record<string, unknown> | unknown[];
  } catch {
    return null;
  }

  if (Array.isArray(parsed)) {
    return null;
  }

  const payload =
    (getNestedValue(parsed, ["event"]) as Record<string, unknown> | undefined) ??
    (getNestedValue(parsed, ["data"]) as Record<string, unknown> | undefined) ??
    (getNestedValue(parsed, ["payload"]) as Record<string, unknown> | undefined);

  const action = pickString(parsed, [
    "action",
    "event",
    "name",
    "type",
    ["event", "action"],
    ["event", "name"],
    ["event", "type"],
    ["data", "action"],
    ["data", "name"],
    ["data", "type"],
    ["payload", "action"],
    ["payload", "name"],
    ["payload", "type"]
  ]);

  if (!action) {
    return null;
  }

  const severity =
    normalizeSeverity(
      pickString(parsed, [
        "severity",
        "risk",
        "level",
        ["event", "severity"],
        ["event", "risk"],
        ["data", "severity"],
        ["data", "risk"],
        ["payload", "severity"],
        ["payload", "risk"]
      ])
    ) || severityFromAction(action);
  const status = normalizeStatus(
    pickString(parsed, [
      "status",
      "phase",
      "outcome",
      "result",
      ["event", "status"],
      ["event", "phase"],
      ["data", "status"],
      ["data", "phase"],
      ["payload", "status"],
      ["payload", "phase"]
    ])
  );
  const runtimeName = pickString(parsed, [
    "runtime",
    "agent",
    "provider",
    "source",
    "service",
    "tool",
    ["event", "runtime"],
    ["event", "agent"],
    ["data", "runtime"],
    ["data", "agent"],
    ["payload", "runtime"],
    ["payload", "agent"]
  ]);
  const targetValue = pickString(parsed, [
    "target",
    "path",
    "file",
    "resource",
    ["event", "target"],
    ["event", "path"],
    ["data", "target"],
    ["data", "path"],
    ["payload", "target"],
    ["payload", "path"]
  ]);
  const target = targetValue ? path.resolve(targetRoot, targetValue) : targetRoot;
  const message = pickString(parsed, [
    "message",
    "summary",
    "text",
    ["event", "message"],
    ["data", "message"],
    ["data", "summary"],
    ["payload", "message"],
    ["payload", "summary"]
  ]) ?? inferMessage(action, status, runtimeName);
  const recommendation =
    pickString(parsed, [
      "recommendation",
      "suggestion",
      ["event", "recommendation"],
      ["data", "recommendation"],
      ["payload", "recommendation"]
    ]) ?? inferRecommendation(action, severity);

  return {
    timestamp: pickString(parsed, [
      "timestamp",
      "time",
      ["event", "timestamp"],
      ["data", "timestamp"],
      ["payload", "timestamp"]
    ]) ?? new Date().toISOString(),
    severity,
    category: "action-event",
    source: "runtime-feed",
    target,
    runtime: runtimeName,
    surfaceKind:
      parsed.surfaceKind === "skill" || parsed.surfaceKind === "project" || parsed.surfaceKind === "runtime"
        ? parsed.surfaceKind
        : "runtime",
    action,
    status,
    message,
    recommendation,
    evidence: {
      source: pickString(parsed, [
        "source",
        ["event", "source"],
        ["data", "source"],
        ["payload", "source"]
      ]) ?? "runtime-event-feed",
      raw: payload ?? parsed
    }
  };
}

export async function discoverRuntimeEventFeeds(targetRoot: string): Promise<RuntimeEventFeed[]> {
  const feedMap = new Map<string, RuntimeEventFeed>();

  for (const relativePath of candidateRelativePaths) {
    const absolutePath = path.join(targetRoot, relativePath);

    try {
      const content = await readFile(absolutePath, "utf8");
      if (content.trim().length === 0) {
        feedMap.set(absolutePath, {
          absolutePath,
          displayPath: displayUserPath(absolutePath)
        });
        continue;
      }

      feedMap.set(absolutePath, {
        absolutePath,
        displayPath: displayUserPath(absolutePath)
      });
    } catch {
      continue;
    }
  }

  const globMatches = await fg(candidateGlobPatterns, {
    cwd: targetRoot,
    absolute: true,
    onlyFiles: true,
    unique: true,
    dot: true,
    deep: 4,
    ignore: ["**/node_modules/**", "**/.git/**"]
  });

  for (const absolutePath of globMatches) {
    feedMap.set(absolutePath, {
      absolutePath,
      displayPath: displayUserPath(absolutePath)
    });
  }

  return [...feedMap.values()].sort((left, right) =>
    left.displayPath.localeCompare(right.displayPath)
  );
}

export async function createRuntimeFeedCursor(feeds: RuntimeEventFeed[]): Promise<RuntimeFeedCursor> {
  const lineCounts = new Map<string, number>();

  for (const feed of feeds) {
    try {
      const content = await readFile(feed.absolutePath, "utf8");
      const lines = content
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
      lineCounts.set(feed.absolutePath, lines.length);
    } catch {
      lineCounts.set(feed.absolutePath, 0);
    }
  }

  return { lineCounts };
}

export async function readNewRuntimeFeedEvents(options: {
  feeds: RuntimeEventFeed[];
  cursor: RuntimeFeedCursor;
  targetRoot: string;
}): Promise<AuditEvent[]> {
  const events: AuditEvent[] = [];

  for (const feed of options.feeds) {
    let content = "";

    try {
      content = await readFile(feed.absolutePath, "utf8");
    } catch {
      options.cursor.lineCounts.set(feed.absolutePath, 0);
      continue;
    }

    const lines = content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    const previousCount = options.cursor.lineCounts.get(feed.absolutePath) ?? 0;
    const startIndex = previousCount > lines.length ? 0 : previousCount;
    const newLines = lines.slice(startIndex);
    options.cursor.lineCounts.set(feed.absolutePath, lines.length);

    for (const line of newLines) {
      const event = parseRuntimeFeedEvent(line, options.targetRoot);
      if (event) {
        events.push(event);
      }
    }
  }

  return events;
}
