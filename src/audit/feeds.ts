import path from "node:path";
import { open, readFile, realpath, stat } from "node:fs/promises";

import fg from "fast-glob";
import YAML from "yaml";

import type { AuditEvent, AuditSeverity } from "./types";
import { actionLabel } from "./presentation";
import { displayUserPath } from "../utils/paths";

export interface RuntimeEventFeed {
  absolutePath: string;
  displayPath: string;
  rootDir: string;
  kind?: "generic-jsonl" | "openclaw-command-log" | "openclaw-gateway-log";
}

export interface RuntimeFeedCursor {
  byteOffsets: Map<string, number>;
  trailingFragments: Map<string, string>;
}

const candidateRelativePaths = [
  ".traceroot/runtime-events.jsonl",
  "runtime-events.jsonl",
  "runtime-events.log",
  "openclaw-events.jsonl",
  "mcp-events.jsonl",
  "mcp-events.log",
  "agent-events.jsonl",
  "agent-events.log",
  "action-events.jsonl",
  "action-events.log",
  path.join("logs", "runtime-events.jsonl"),
  path.join("logs", "runtime-events.log"),
  path.join("logs", "openclaw-events.jsonl"),
  path.join("logs", "mcp-events.jsonl"),
  path.join("logs", "mcp-events.log"),
  path.join("logs", "agent-events.jsonl"),
  path.join("logs", "agent-events.log"),
  path.join("logs", "action-events.jsonl"),
  path.join("logs", "action-events.log"),
  path.join(".openclaw", "events.jsonl"),
  path.join(".mcp", "events.jsonl"),
  path.join(".mcp", "events.log"),
  path.join("logs", "commands.log"),
  path.join("logs", "gateway.log"),
  path.join("logs", "gateway.err.log")
];

const candidateGlobPatterns = [
  "logs/**/*events*.jsonl",
  "logs/**/*events*.log",
  "logs/**/*actions*.jsonl",
  "logs/**/*actions*.log",
  ".openclaw/**/*events*.jsonl",
  ".openclaw/**/*actions*.jsonl",
  ".mcp/**/*events*.jsonl",
  ".mcp/**/*events*.log",
  ".mcp/**/*actions*.jsonl",
  ".mcp/**/*actions*.log",
  "logs/**/*mcp*.log",
  ".mcp/**/*mcp*.log",
  "logs/**/*commands*.log",
  ".openclaw/**/*commands*.log"
];

function classifyFeedKind(absolutePath: string): RuntimeEventFeed["kind"] {
  const basename = path.basename(absolutePath).toLowerCase();

  if (basename === "commands.log") {
    return "openclaw-command-log";
  }

  if (
    basename === "gateway.log" ||
    basename === "gateway.err.log" ||
    basename === "openclaw-gateway.log" ||
    /^openclaw-\d{4}-\d{2}-\d{2}\.log$/.test(basename)
  ) {
    return "openclaw-gateway-log";
  }

  return "generic-jsonl";
}

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

function inferActionFromText(message: string): string | undefined {
  const normalized = message.trim().toLowerCase();

  if (/(send|draft).*(email|mail)|(email|mail).*(send|draft)/.test(normalized)) {
    return "send-email";
  }

  if (/(publish|post|tweet|social|tiktok|youtube|linkedin|reddit)/.test(normalized)) {
    return "public-post";
  }

  if (/(message|whatsapp|telegram|slack|discord|wechat)/.test(normalized)) {
    return "send-message";
  }

  if (/(delete|remove|rm|unlink|wipe|purge)/.test(normalized)) {
    return "delete-files";
  }

  if (
    /(write|modify|edit|update|rename|move|copy)/.test(normalized) &&
    /(file|files|fs|disk|path|workspace)/.test(normalized)
  ) {
    return "modify-files";
  }

  if (/(payment|purchase|checkout|order|stripe|paypal|wallet)/.test(normalized)) {
    return "purchase-or-payment";
  }

  if (/(bank|finance|broker|trade|portfolio|account-balance)/.test(normalized)) {
    return "bank-access";
  }

  if (/(secret|token|credential|password|key)/.test(normalized)) {
    return "sensitive-secret-access";
  }

  if (/(sensitive|private|customer-data|pii|record|records)/.test(normalized)) {
    return "sensitive-data-access";
  }

  return undefined;
}

function inferStatusFromMessage(message: string): AuditEvent["status"] {
  const normalized = message.trim().toLowerCase();

  if (/(attempt|attempting|trying|starting|about to|preparing to)/.test(normalized)) {
    return "attempted";
  }

  if (/(failed|failure|error|unable to|denied|refused)/.test(normalized)) {
    return "failed";
  }

  if (/(completed|finished|sent|published|posted|deleted|removed|updated)/.test(normalized)) {
    return "succeeded";
  }

  return "observed";
}

function inferActionFromToolName(name?: string): string | undefined {
  if (!name) {
    return undefined;
  }

  const normalized = name.replace(/[_./]+/g, " ").replace(/-/g, " ").trim();
  return inferActionFromText(normalized) ?? inferActionFromText(name);
}

function inferChannelFromText(message: string): string | undefined {
  const normalized = message.trim().toLowerCase();

  if (/\btelegram\b/.test(normalized)) {
    return "telegram";
  }

  if (/\bwhatsapp\b/.test(normalized)) {
    return "whatsapp";
  }

  if (/\bslack\b/.test(normalized)) {
    return "slack";
  }

  if (/\bdiscord\b/.test(normalized)) {
    return "discord";
  }

  if (/\bsignal\b/.test(normalized)) {
    return "signal";
  }

  if (/\bimessage\b/.test(normalized)) {
    return "imessage";
  }

  if (/\bgoogle\s*chat\b/.test(normalized)) {
    return "googlechat";
  }

  if (/\bmattermost\b/.test(normalized)) {
    return "mattermost";
  }

  if (/\b(msteams|microsoft\s*teams)\b/.test(normalized)) {
    return "msteams";
  }

  if (/\bwechat\b/.test(normalized)) {
    return "wechat";
  }

  return undefined;
}

function inferSenderFromText(message: string): string | undefined {
  const handleMatch = message.match(/(^|[\s(])(@[A-Za-z0-9_.-]+)/);
  if (handleMatch?.[2]) {
    return handleMatch[2];
  }

  const phoneMatch = message.match(/(\+\d[\d\s-]{6,}\d)/);
  if (phoneMatch?.[1]) {
    return phoneMatch[1].replace(/\s+/g, " ").trim();
  }

  const senderMatch = message.match(
    /\b(?:sender|user|actor|from)\s*[:=]\s*("?)([A-Za-z0-9_.@+-]+)\1/i
  );
  if (senderMatch?.[2]) {
    return senderMatch[2];
  }

  return undefined;
}

function inferTargetFromText(message: string, targetRoot: string): string {
  const targetMatch = message.match(
    /\b(?:path|file|target|resource)\s*[:=]\s*("?)([^"\s)]+)\1/i
  );

  if (!targetMatch?.[2]) {
    return targetRoot;
  }

  return path.resolve(targetRoot, targetMatch[2]);
}

function parsePlainTextMcpToolCallLine(line: string, targetRoot: string): AuditEvent | null {
  const trimmed = line.trim();
  if (!trimmed) {
    return null;
  }

  const textMatch =
    trimmed.match(
      /^(?<timestamp>\d{4}-\d{2}-\d{2}[T ][^ ]+)\s+(?<level>[A-Z]+)\s+(?<scope>[A-Za-z0-9_.-]+)[:\s-]+(?<message>.+)$/i
    ) ??
    trimmed.match(
      /^\[(?<timestamp>[^\]]+)\]\s+(?<level>[A-Z]+)\s+(?<scope>[A-Za-z0-9_.-]+)[:\s-]+(?<message>.+)$/i
    );

  const timestampValue = textMatch?.groups?.timestamp?.trim();
  const levelValue = textMatch?.groups?.level?.trim();
  const scopeValue = textMatch?.groups?.scope?.trim();
  const message = textMatch?.groups?.message?.trim() ?? trimmed;
  const normalizedMessage = message.toLowerCase();

  if (
    !/(tools\/call|tool\s+call|tool-call|mcp\s+tool|calling\s+tool|invoking\s+tool)/i.test(
      normalizedMessage
    )
  ) {
    return null;
  }

  const toolName =
    message.match(/\btools\/call(?:\s+name=|\s+tool=|\s+)([A-Za-z0-9_.:/-]+)/i)?.[1] ??
    message.match(/\btool(?:\s+call|[-\s]call)?(?:\s+for|\s+to|\s*:)?\s*([A-Za-z0-9_.:/-]+)/i)
      ?.[1] ??
    message.match(/\bmcp\s+tool(?:\s+for|\s+to|\s*:)?\s*([A-Za-z0-9_.:/-]+)/i)?.[1] ??
    message.match(/\b(?:calling|invoking)\s+tool\s+([A-Za-z0-9_.:/-]+)/i)?.[1] ??
    message.match(/\btool\s*=\s*([A-Za-z0-9_.:/-]+)/i)?.[1];

  const action = inferActionFromToolName(toolName) ?? inferActionFromText(message);
  if (!action) {
    return null;
  }

  const severity = normalizeSeverity(levelValue) ?? severityFromAction(action);
  const runtimeName =
    scopeValue && !["tool", "tools", "mcp", "gateway"].includes(scopeValue.toLowerCase())
      ? scopeValue
      : "mcp";
  const channel = inferChannelFromText(message);
  const sender = inferSenderFromText(message);
  const humanAction = actionLabel(action);
  const toolLabel = toolName ?? action;

  return {
    timestamp: timestampValue ?? new Date().toISOString(),
    severity,
    category: "action-event",
    source: "runtime-feed",
    target: inferTargetFromText(message, targetRoot),
    runtime: runtimeName,
    surfaceKind: "runtime",
    action,
    status: (() => {
      const inferredStatus = inferStatusFromMessage(message);
      return inferredStatus === "observed" ? "attempted" : inferredStatus;
    })(),
    message:
      toolName && toolName !== action
        ? `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}。`,
    recommendation: inferRecommendation(action, severity),
    evidence: {
      source: "mcp-tool-call-log",
      toolName,
      channel,
      sender,
      rawLine: trimmed
    }
  };
}

function inferStructuredRuntimeFeedEvent(
  parsed: Record<string, unknown>,
  targetRoot: string
): AuditEvent | null {
  const method = pickString(parsed, [
    "method",
    "type",
    ["event", "method"],
    ["event", "type"],
    ["data", "method"],
    ["data", "type"],
    ["payload", "method"],
    ["payload", "type"]
  ]);
  const toolName = pickString(parsed, [
    ["params", "name"],
    ["params", "tool"],
    ["event", "params", "name"],
    ["event", "params", "tool"],
    ["data", "params", "name"],
    ["data", "params", "tool"],
    ["payload", "params", "name"],
    ["payload", "params", "tool"]
  ]);

  const looksLikeToolCall =
    typeof method === "string" &&
    /(tools\/call|tool.call|tool-call|mcp.tool.call)/i.test(method);

  const action = inferActionFromToolName(toolName);
  if (!looksLikeToolCall || !action) {
    return null;
  }

  const hasError =
    getNestedValue(parsed, ["error"]) !== undefined ||
    getNestedValue(parsed, ["event", "error"]) !== undefined ||
    getNestedValue(parsed, ["data", "error"]) !== undefined ||
    getNestedValue(parsed, ["payload", "error"]) !== undefined;
  const hasResult =
    getNestedValue(parsed, ["result"]) !== undefined ||
    getNestedValue(parsed, ["event", "result"]) !== undefined ||
    getNestedValue(parsed, ["data", "result"]) !== undefined ||
    getNestedValue(parsed, ["payload", "result"]) !== undefined;

  const explicitStatus = pickString(parsed, [
    "status",
    "phase",
    "outcome",
    ["event", "status"],
    ["data", "status"],
    ["payload", "status"]
  ]);
  const status = explicitStatus
    ? normalizeStatus(explicitStatus)
    : hasError
      ? "failed"
      : hasResult
        ? "succeeded"
        : "attempted";

  const runtimeName =
    pickString(parsed, [
      "runtime",
      "agent",
      "provider",
      "service",
      "server",
      "mcpServer",
      ["event", "runtime"],
      ["event", "service"],
      ["data", "runtime"],
      ["data", "service"],
      ["payload", "runtime"],
      ["payload", "service"]
    ]) ?? "mcp";
  const channel =
    pickString(parsed, [
      "channel",
      "source",
      ["event", "channel"],
      ["event", "source"],
      ["data", "channel"],
      ["data", "source"],
      ["payload", "channel"],
      ["payload", "source"]
    ]) ?? undefined;
  const sender =
    pickString(parsed, [
      "sender",
      "senderId",
      "user",
      "userId",
      "actor",
      ["event", "sender"],
      ["event", "senderId"],
      ["event", "user"],
      ["event", "userId"],
      ["data", "sender"],
      ["data", "senderId"],
      ["data", "user"],
      ["data", "userId"],
      ["payload", "sender"],
      ["payload", "senderId"],
      ["payload", "user"],
      ["payload", "userId"]
    ]) ?? undefined;
  const sessionKey =
    pickString(parsed, [
      "sessionKey",
      "sessionId",
      "threadId",
      "conversationId",
      ["event", "sessionKey"],
      ["event", "sessionId"],
      ["data", "sessionKey"],
      ["data", "sessionId"],
      ["payload", "sessionKey"],
      ["payload", "sessionId"]
    ]) ?? undefined;

  const targetValue = pickString(parsed, [
    "target",
    "path",
    "file",
    "resource",
    ["params", "path"],
    ["params", "file"],
    ["data", "params", "path"],
    ["data", "params", "file"],
    ["payload", "params", "path"],
    ["payload", "params", "file"]
  ]);
  const target = targetValue ? path.resolve(targetRoot, targetValue) : targetRoot;
  const toolLabel = toolName ?? action;
  const humanAction = actionLabel(action);
  const severity =
    normalizeSeverity(
      pickString(parsed, [
        "severity",
        "risk",
        "level",
        ["event", "severity"],
        ["data", "severity"],
        ["payload", "severity"]
      ])
    ) ?? severityFromAction(action);

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
    surfaceKind: "runtime",
    action,
    status,
    message:
      toolName && toolName !== action
        ? `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}。`,
    recommendation: inferRecommendation(action, severity),
    evidence: {
      source: "mcp-tool-call",
      method,
      toolName,
      channel,
      sender,
      sessionKey,
      raw: parsed
    }
  };
}

function parseOpenClawCommandLogLine(line: string, targetRoot: string): AuditEvent | null {
  let parsed: Record<string, unknown>;

  try {
    parsed = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return null;
  }

  const action = pickString(parsed, ["action"]);
  if (!action) {
    return null;
  }

  const sourceChannel = pickString(parsed, ["source"]) ?? "openclaw";
  const sender = pickString(parsed, ["senderId"]);
  const sessionKey = pickString(parsed, ["sessionKey"]);
  const normalized = action.toLowerCase();

  let message = `OpenClaw 刚收到一个控制命令：${action}。`;
  if (normalized === "new") {
    message = `OpenClaw 刚收到一个新任务启动命令（来源：${sourceChannel}）。`;
  } else if (normalized === "stop") {
    message = `OpenClaw 刚收到一个停止命令（来源：${sourceChannel}）。`;
  } else if (normalized === "resume") {
    message = `OpenClaw 刚收到一个恢复运行命令（来源：${sourceChannel}）。`;
  }

  if (sender) {
    message += ` 发送方：${sender}。`;
  }

  return {
    timestamp: pickString(parsed, ["timestamp"]) ?? new Date().toISOString(),
    severity: "safe",
    category: "action-event",
    source: "runtime-feed",
    target: targetRoot,
    runtime: "openclaw",
    surfaceKind: "runtime",
    action: `openclaw-command-${normalized}`,
    status: "observed",
    message,
    evidence: {
      source: "openclaw-command-logger",
      sessionKey,
      channel: sourceChannel,
      sender,
      raw: parsed
    }
  };
}

function parseOpenClawGatewayLogLine(line: string, targetRoot: string): AuditEvent | null {
  const plainTextEvent = parseOpenClawGatewayTextLine(line, targetRoot);
  if (plainTextEvent) {
    return plainTextEvent;
  }

  let parsed: Record<string, unknown>;

  try {
    parsed = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return null;
  }

  const message =
    pickString(parsed, ["msg", "message", "text", ["log", "message"]]) ?? "";
  if (!message) {
    return null;
  }

  const action = inferActionFromText(message);
  if (!action) {
    return null;
  }

  const severity =
    normalizeSeverity(pickString(parsed, ["level", "severity", "risk"])) ??
    severityFromAction(action);
  const subsystem = pickString(parsed, ["subsystem", "logger", "scope"]);
  const runtimeName = pickString(parsed, ["runtime", "service"]) ?? "openclaw";
  const channel =
    pickString(parsed, ["channel", "source", "provider", "chat", "account"]) ??
    inferChannelFromText(message) ??
    undefined;
  const sender =
    pickString(parsed, ["sender", "senderId", "user", "userId", "actor"]) ??
    inferSenderFromText(message) ??
    undefined;
  const sessionKey =
    pickString(parsed, ["sessionKey", "sessionId", "threadId", "conversationId"]) ?? undefined;
  const targetValue = pickString(parsed, ["target", "path", "file"]);
  const target = targetValue
    ? path.resolve(targetRoot, targetValue)
    : inferTargetFromText(message, targetRoot);

  return {
    timestamp: pickString(parsed, ["timestamp", "time"]) ?? new Date().toISOString(),
    severity,
    category: "action-event",
    source: "runtime-feed",
    target,
    runtime: runtimeName,
    surfaceKind: "runtime",
    action,
    status: inferStatusFromMessage(message),
    message: `${runtimeName} 刚提到：${message}`,
    recommendation: inferRecommendation(action, severity),
    evidence: {
      source: "openclaw-gateway-log",
      subsystem,
      channel,
      sender,
      sessionKey,
      raw: parsed
    }
  };
}

function parseOpenClawGatewayTextLine(line: string, targetRoot: string): AuditEvent | null {
  const trimmed = line.trim();
  if (!trimmed) {
    return null;
  }

  const textMatch =
    trimmed.match(
      /^(?<timestamp>\d{4}-\d{2}-\d{2}[T ][^ ]+)\s+(?<level>[A-Z]+)\s+(?<scope>[A-Za-z0-9_.-]+)[:\s-]+(?<message>.+)$/i
    ) ??
    trimmed.match(
      /^\[(?<timestamp>[^\]]+)\]\s+(?<level>[A-Z]+)\s+(?<scope>[A-Za-z0-9_.-]+)[:\s-]+(?<message>.+)$/i
    );

  const timestampValue = textMatch?.groups?.timestamp?.trim();
  const levelValue = textMatch?.groups?.level?.trim();
  const scopeValue = textMatch?.groups?.scope?.trim();
  const message = textMatch?.groups?.message?.trim() ?? trimmed;
  const action = inferActionFromText(message);

  if (!action) {
    return null;
  }

  const severity = normalizeSeverity(levelValue) ?? severityFromAction(action);
  const channel = inferChannelFromText(message);
  const sender = inferSenderFromText(message);

  return {
    timestamp: timestampValue ?? new Date().toISOString(),
    severity,
    category: "action-event",
    source: "runtime-feed",
    target: inferTargetFromText(message, targetRoot),
    runtime: "openclaw",
    surfaceKind: "runtime",
    action,
    status: inferStatusFromMessage(message),
    message: `openclaw 刚提到：${message}`,
    recommendation: inferRecommendation(action, severity),
    evidence: {
      source: "openclaw-gateway-log",
      subsystem: scopeValue,
      channel,
      sender,
      rawLine: trimmed
    }
  };
}

function parseRuntimeFeedEvent(
  line: string,
  targetRoot: string,
  feedKind: RuntimeEventFeed["kind"] = "generic-jsonl"
): AuditEvent | null {
  if (feedKind === "openclaw-command-log") {
    return parseOpenClawCommandLogLine(line, targetRoot);
  }

  if (feedKind === "openclaw-gateway-log") {
    return parseOpenClawGatewayLogLine(line, targetRoot);
  }

  let parsed: Record<string, unknown> | unknown[];

  try {
    parsed = JSON.parse(line) as Record<string, unknown> | unknown[];
  } catch {
    return parsePlainTextMcpToolCallLine(line, targetRoot);
  }

  if (Array.isArray(parsed)) {
    return null;
  }

  const payload =
    (getNestedValue(parsed, ["event"]) as Record<string, unknown> | undefined) ??
    (getNestedValue(parsed, ["data"]) as Record<string, unknown> | undefined) ??
    (getNestedValue(parsed, ["payload"]) as Record<string, unknown> | undefined);

  const structuredEvent = inferStructuredRuntimeFeedEvent(parsed, targetRoot);
  if (structuredEvent) {
    return structuredEvent;
  }

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
  const channel =
    pickString(parsed, [
      "channel",
      "sourceChannel",
      "inputChannel",
      "chatChannel",
      "source",
      ["event", "channel"],
      ["event", "sourceChannel"],
      ["data", "channel"],
      ["data", "sourceChannel"],
      ["payload", "channel"],
      ["payload", "sourceChannel"]
    ]) ?? undefined;
  const sender =
    pickString(parsed, [
      "sender",
      "senderId",
      "user",
      "userId",
      "actor",
      "from",
      ["event", "sender"],
      ["event", "senderId"],
      ["event", "user"],
      ["data", "sender"],
      ["data", "senderId"],
      ["data", "user"],
      ["payload", "sender"],
      ["payload", "senderId"],
      ["payload", "user"]
    ]) ?? undefined;
  const sessionKey =
    pickString(parsed, [
      "sessionKey",
      "sessionId",
      "threadId",
      "conversationId",
      ["event", "sessionKey"],
      ["event", "sessionId"],
      ["data", "sessionKey"],
      ["data", "sessionId"],
      ["payload", "sessionKey"],
      ["payload", "sessionId"]
    ]) ?? undefined;
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
      channel,
      sender,
      sessionKey,
      raw: payload ?? parsed
    }
  };
}

type CompanionFeed = {
  absolutePath: string;
  kind: RuntimeEventFeed["kind"];
};

function collectNestedLogPathCandidates(options: {
  source: unknown;
  candidates: Map<string, CompanionFeed>;
  targetRoot: string;
}): void {
  const visit = (value: unknown, pathSegments: string[] = []): void => {
    if (typeof value === "string") {
      const currentKey = pathSegments[pathSegments.length - 1]?.toLowerCase() ?? "";
      const parentSegments = pathSegments.slice(0, -1).map((segment) => segment.toLowerCase());
      const looksLikeLogPath =
        ["file", "files", "path"].includes(currentKey) &&
        parentSegments.some((segment) =>
          /(log|logs|event|events|audit|trace)/.test(segment)
        );

      if (looksLikeLogPath) {
        addCompanionFeedCandidate({
          candidates: options.candidates,
          targetRoot: options.targetRoot,
          value,
          kind: classifyFeedKind(path.resolve(options.targetRoot, value))
        });
      }

      return;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (typeof entry === "string") {
          const currentKey = pathSegments[pathSegments.length - 1]?.toLowerCase() ?? "";
          const parentSegments = pathSegments.slice(0, -1).map((segment) =>
            segment.toLowerCase()
          );
          const looksLikeLogPath =
            currentKey === "files" &&
            parentSegments.some((segment) =>
              /(log|logs|event|events|audit|trace)/.test(segment)
            );

          if (looksLikeLogPath) {
            addCompanionFeedCandidate({
              candidates: options.candidates,
              targetRoot: options.targetRoot,
              value: entry,
              kind: classifyFeedKind(path.resolve(options.targetRoot, entry))
            });
          }
        } else {
          visit(entry, pathSegments);
        }
      }

      return;
    }

    if (!value || typeof value !== "object") {
      return;
    }

    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      visit(child, [...pathSegments, key]);
    }
  };

  visit(options.source, []);
}

function addCompanionFeedCandidate(options: {
  candidates: Map<string, CompanionFeed>;
  targetRoot: string;
  value: unknown;
  kind?: RuntimeEventFeed["kind"];
}): void {
  const pushPath = (rawPath: string): void => {
    if (!rawPath.trim()) {
      return;
    }

    const absolutePath = path.resolve(options.targetRoot, rawPath.trim());
    options.candidates.set(absolutePath, {
      absolutePath,
      kind: options.kind ?? classifyFeedKind(absolutePath)
    });
  };

  if (typeof options.value === "string") {
    pushPath(options.value);
    return;
  }

  if (Array.isArray(options.value)) {
    for (const entry of options.value) {
      if (typeof entry === "string") {
        pushPath(entry);
      }
    }
  }
}

async function discoverOpenClawCompanionFeeds(targetRoot: string): Promise<CompanionFeed[]> {
  const rootName = path.basename(targetRoot).toLowerCase();
  const looksLikeOpenClawRoot =
    rootName.startsWith(".openclaw") || rootName.includes("openclaw");
  const candidates = new Map<string, CompanionFeed>();
  let hasOpenClawConfig = false;

  for (const configName of ["openclaw.json", "openclaw.yaml", "openclaw.yml"]) {
    try {
      const configRaw = await readFile(path.join(targetRoot, configName), "utf8");
      const config =
        configName === "openclaw.json"
          ? (JSON.parse(configRaw) as Record<string, unknown>)
          : (YAML.parse(configRaw) as Record<string, unknown>);
      hasOpenClawConfig = true;

      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["logging", "file"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["logging", "files"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["logging", "gateway", "file"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["logging", "gateway", "files"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["logging", "gateway", "path"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["gateway", "file"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["gateway", "files"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["gateway", "path"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["logs", "file"])
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["logs", "files"])
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["runtimeLogs", "file"])
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["runtimeLogs", "files"])
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["paths", "logs"])
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["paths", "logs", "gateway"]),
        kind: "openclaw-gateway-log"
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["paths", "logs", "runtime"])
      });
      addCompanionFeedCandidate({
        candidates,
        targetRoot,
        value: getNestedValue(config, ["paths", "logs", "events"])
      });

      break;
    } catch {
      // ignore invalid or missing config and continue to the next supported format
    }
  }

  if (looksLikeOpenClawRoot || hasOpenClawConfig) {
    const defaultLogs = await fg("/tmp/openclaw/openclaw-*.log", {
      absolute: true,
      onlyFiles: true,
      unique: true
    });

    for (const filePath of defaultLogs) {
      candidates.set(filePath, {
        absolutePath: filePath,
        kind: classifyFeedKind(filePath)
      });
    }
  }

  return [...candidates.values()];
}

async function discoverMcpCompanionFeeds(targetRoot: string): Promise<CompanionFeed[]> {
  const rootName = path.basename(targetRoot).toLowerCase();
  const looksLikeMcpRoot = rootName.startsWith(".mcp") || rootName.includes("mcp");
  const candidates = new Map<string, CompanionFeed>();
  const configCandidates = [
    "mcp.json",
    "mcp.yaml",
    "mcp.yml",
    "mcp.config.json",
    "mcp.config.yaml",
    "mcp.config.yml",
    "mcp-config.json",
    "mcp-config.yaml",
    "mcp-config.yml",
    "mcpServers.json",
    "mcpServers.yaml",
    "mcpServers.yml",
    "mcp-servers.json",
    "mcp-servers.yaml",
    "mcp-servers.yml",
    ...(looksLikeMcpRoot ? ["config.json", "config.yaml", "config.yml"] : [])
  ];
  let hasMcpConfig = false;

  for (const configName of configCandidates) {
    try {
      const configRaw = await readFile(path.join(targetRoot, configName), "utf8");
      const config =
        configName.endsWith(".json")
          ? (JSON.parse(configRaw) as Record<string, unknown>)
          : (YAML.parse(configRaw) as Record<string, unknown>);

      hasMcpConfig = true;
      collectNestedLogPathCandidates({
        source: config,
        candidates,
        targetRoot
      });
    } catch {
      // ignore invalid or missing config and continue to the next supported format
    }
  }

  if (looksLikeMcpRoot || hasMcpConfig) {
    const defaultLogs = await fg(
      [
        path.join(targetRoot, "**", "*mcp*.log"),
        path.join(targetRoot, "**", "*mcp*.jsonl"),
        path.join(targetRoot, "**", "*events*.log"),
        path.join(targetRoot, "**", "*events*.jsonl")
      ],
      {
        absolute: true,
        onlyFiles: true,
        unique: true,
        dot: true,
        ignore: ["**/node_modules/**", "**/.git/**"]
      }
    );

    for (const filePath of defaultLogs) {
      candidates.set(filePath, {
        absolutePath: filePath,
        kind: classifyFeedKind(filePath)
      });
    }
  }

  return [...candidates.values()];
}

async function canonicalFeedPath(candidatePath: string): Promise<string> {
  try {
    return await realpath(candidatePath);
  } catch {
    return path.resolve(candidatePath);
  }
}

export async function discoverRuntimeEventFeeds(targetRoot: string): Promise<RuntimeEventFeed[]> {
  const feedMap = new Map<string, RuntimeEventFeed>();

  for (const relativePath of candidateRelativePaths) {
    const candidatePath = path.join(targetRoot, relativePath);

    try {
      const content = await readFile(candidatePath, "utf8");
      const absolutePath = await canonicalFeedPath(candidatePath);
      if (content.trim().length === 0) {
        feedMap.set(absolutePath, {
          absolutePath,
          displayPath: displayUserPath(absolutePath),
          rootDir: targetRoot,
          kind: classifyFeedKind(absolutePath)
        });
        continue;
      }

      feedMap.set(absolutePath, {
        absolutePath,
        displayPath: displayUserPath(absolutePath),
        rootDir: targetRoot,
        kind: classifyFeedKind(absolutePath)
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

  for (const matchedPath of globMatches) {
    const absolutePath = await canonicalFeedPath(matchedPath);
    feedMap.set(absolutePath, {
      absolutePath,
      displayPath: displayUserPath(absolutePath),
      rootDir: targetRoot,
      kind: classifyFeedKind(absolutePath)
    });
  }

  const companionFeeds = await discoverOpenClawCompanionFeeds(targetRoot);
  for (const companionFeed of companionFeeds) {
    const absolutePath = await canonicalFeedPath(companionFeed.absolutePath);
    feedMap.set(absolutePath, {
      absolutePath,
      displayPath: displayUserPath(absolutePath),
      rootDir: targetRoot,
      kind: companionFeed.kind ?? classifyFeedKind(absolutePath)
    });
  }

  const mcpCompanionFeeds = await discoverMcpCompanionFeeds(targetRoot);
  for (const companionFeed of mcpCompanionFeeds) {
    const absolutePath = await canonicalFeedPath(companionFeed.absolutePath);
    feedMap.set(absolutePath, {
      absolutePath,
      displayPath: displayUserPath(absolutePath),
      rootDir: targetRoot,
      kind: companionFeed.kind ?? classifyFeedKind(absolutePath)
    });
  }

  return [...feedMap.values()].sort((left, right) =>
    left.displayPath.localeCompare(right.displayPath)
  );
}

export async function createRuntimeFeedCursor(feeds: RuntimeEventFeed[]): Promise<RuntimeFeedCursor> {
  const byteOffsets = new Map<string, number>();
  const trailingFragments = new Map<string, string>();

  for (const feed of feeds) {
    try {
      const feedStats = await stat(feed.absolutePath);
      byteOffsets.set(feed.absolutePath, feedStats.size);
      trailingFragments.set(feed.absolutePath, "");
    } catch {
      byteOffsets.set(feed.absolutePath, 0);
      trailingFragments.set(feed.absolutePath, "");
    }
  }

  return { byteOffsets, trailingFragments };
}

export async function readRecentRuntimeFeedEvents(options: {
  feeds: RuntimeEventFeed[];
  targetRoot: string;
  maxLinesPerFeed?: number;
  maxAgeMs?: number;
}): Promise<AuditEvent[]> {
  const events: AuditEvent[] = [];
  const maxLinesPerFeed = options.maxLinesPerFeed ?? 20;
  const maxAgeMs = options.maxAgeMs ?? 5 * 60_000;
  const now = Date.now();

  for (const feed of options.feeds) {
    let content = "";

    try {
      content = await readFile(feed.absolutePath, "utf8");
    } catch {
      continue;
    }

    const lines = content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .slice(-maxLinesPerFeed);

    for (const line of lines) {
      const event = parseRuntimeFeedEvent(
        line,
        feed.rootDir ?? options.targetRoot,
        feed.kind
      );

      if (!event) {
        continue;
      }

      const eventTime = new Date(event.timestamp).getTime();
      if (!Number.isNaN(eventTime) && now - eventTime > maxAgeMs) {
        continue;
      }

      event.evidence = {
        ...(event.evidence ?? {}),
        feedPath: feed.absolutePath
      };
      events.push(event);
    }
  }

  return events;
}

function isTodayTimestamp(timestampValue: string): boolean {
  const timestamp = new Date(timestampValue);

  if (Number.isNaN(timestamp.getTime())) {
    return false;
  }

  return timestamp.toDateString() === new Date().toDateString();
}

export async function readTodaysRuntimeFeedEvents(options: {
  feeds: RuntimeEventFeed[];
  targetRoot: string;
  maxLinesPerFeed?: number;
}): Promise<AuditEvent[]> {
  const events: AuditEvent[] = [];
  const maxLinesPerFeed = options.maxLinesPerFeed ?? 200;

  for (const feed of options.feeds) {
    let content = "";

    try {
      content = await readFile(feed.absolutePath, "utf8");
    } catch {
      continue;
    }

    const lines = content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .slice(-maxLinesPerFeed);

    for (const line of lines) {
      const event = parseRuntimeFeedEvent(
        line,
        feed.rootDir ?? options.targetRoot,
        feed.kind
      );

      if (!event || !isTodayTimestamp(event.timestamp)) {
        continue;
      }

      event.evidence = {
        ...(event.evidence ?? {}),
        feedPath: feed.absolutePath
      };
      events.push(event);
    }
  }

  return events;
}

export async function readNewRuntimeFeedEvents(options: {
  feeds: RuntimeEventFeed[];
  cursor: RuntimeFeedCursor;
  targetRoot: string;
}): Promise<AuditEvent[]> {
  const events: AuditEvent[] = [];

  for (const feed of options.feeds) {
    let feedSize = 0;

    try {
      feedSize = (await stat(feed.absolutePath)).size;
    } catch {
      options.cursor.byteOffsets.set(feed.absolutePath, 0);
      options.cursor.trailingFragments.set(feed.absolutePath, "");
      continue;
    }

    let previousOffset = options.cursor.byteOffsets.get(feed.absolutePath) ?? 0;
    let trailingFragment = options.cursor.trailingFragments.get(feed.absolutePath) ?? "";

    if (feedSize < previousOffset) {
      previousOffset = 0;
      trailingFragment = "";
    }

    if (feedSize === previousOffset) {
      continue;
    }

    const byteLength = feedSize - previousOffset;
    const fileHandle = await open(feed.absolutePath, "r");
    let chunk = "";

    try {
      const buffer = Buffer.allocUnsafe(byteLength);
      const { bytesRead } = await fileHandle.read(buffer, 0, byteLength, previousOffset);
      chunk = buffer.subarray(0, bytesRead).toString("utf8");
    } finally {
      await fileHandle.close();
    }

    const combined = `${trailingFragment}${chunk}`;
    const endsWithLineBreak = /(?:\r?\n)$/.test(combined);
    const rawLines = combined.split(/\r?\n/);
    const nextTrailingFragment = endsWithLineBreak ? "" : rawLines.pop() ?? "";

    options.cursor.byteOffsets.set(feed.absolutePath, feedSize);
    options.cursor.trailingFragments.set(feed.absolutePath, nextTrailingFragment);

    for (const line of rawLines.map((value) => value.trim()).filter((value) => value.length > 0)) {
      const event = parseRuntimeFeedEvent(
        line,
        feed.rootDir ?? options.targetRoot,
        feed.kind
      );
      if (event) {
        event.evidence = {
          ...(event.evidence ?? {}),
          feedPath: feed.absolutePath
        };
        events.push(event);
      }
    }
  }

  return events;
}
