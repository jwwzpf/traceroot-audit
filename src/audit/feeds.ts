import path from "node:path";
import { readFile } from "node:fs/promises";

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
  path.join("logs", "runtime-events.jsonl"),
  path.join("logs", "openclaw-events.jsonl"),
  path.join("logs", "mcp-events.jsonl"),
  path.join(".openclaw", "events.jsonl")
];

function normalizeSeverity(value?: unknown): AuditSeverity {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (["critical", "crit", "severe"].includes(normalized)) {
    return "critical";
  }

  if (["high-risk", "high", "danger", "warning-high"].includes(normalized)) {
    return "high-risk";
  }

  if (["risky", "risk", "warning", "medium"].includes(normalized)) {
    return "risky";
  }

  return "safe";
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
  let parsed: Record<string, unknown>;

  try {
    parsed = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return null;
  }

  const action =
    typeof parsed.action === "string"
      ? parsed.action
      : typeof parsed.event === "string"
        ? parsed.event
        : typeof parsed.name === "string"
          ? parsed.name
          : undefined;

  if (!action) {
    return null;
  }

  const severity = normalizeSeverity(parsed.severity ?? parsed.risk ?? parsed.level) || severityFromAction(action);
  const status = normalizeStatus(parsed.status ?? parsed.phase ?? parsed.outcome);
  const runtimeName =
    typeof parsed.runtime === "string"
      ? parsed.runtime
      : typeof parsed.agent === "string"
        ? parsed.agent
        : typeof parsed.provider === "string"
          ? parsed.provider
          : undefined;
  const target =
    typeof parsed.target === "string"
      ? path.resolve(targetRoot, parsed.target)
      : typeof parsed.path === "string"
        ? path.resolve(targetRoot, parsed.path)
        : targetRoot;
  const message =
    typeof parsed.message === "string" && parsed.message.trim().length > 0
      ? parsed.message
      : inferMessage(action, status, runtimeName);

  return {
    timestamp:
      typeof parsed.timestamp === "string" && parsed.timestamp.length > 0
        ? parsed.timestamp
        : new Date().toISOString(),
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
    recommendation:
      typeof parsed.recommendation === "string" && parsed.recommendation.trim().length > 0
        ? parsed.recommendation
        : inferRecommendation(action, severity),
    evidence: {
      source: typeof parsed.source === "string" ? parsed.source : "runtime-event-feed",
      raw: parsed
    }
  };
}

export async function discoverRuntimeEventFeeds(targetRoot: string): Promise<RuntimeEventFeed[]> {
  const feeds: RuntimeEventFeed[] = [];

  for (const relativePath of candidateRelativePaths) {
    const absolutePath = path.join(targetRoot, relativePath);

    try {
      const content = await readFile(absolutePath, "utf8");
      if (content.trim().length === 0) {
        feeds.push({
          absolutePath,
          displayPath: displayUserPath(absolutePath)
        });
        continue;
      }

      feeds.push({
        absolutePath,
        displayPath: displayUserPath(absolutePath)
      });
    } catch {
      continue;
    }
  }

  return feeds;
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
