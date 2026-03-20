import os from "node:os";
import path from "node:path";
import { open, readFile, realpath, stat } from "node:fs/promises";

import fg from "fast-glob";
import JSON5 from "json5";
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

export interface NativeRuntimeFeedRoot {
  absolutePath: string;
  displayPath: string;
}

export interface RuntimeFeedCursor {
  byteOffsets: Map<string, number>;
  trailingFragments: Map<string, string>;
}

const clawFamilyNames = ["openclaw", "claw", "lobster"] as const;

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
  path.join(".lobster", "events.jsonl"),
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
  ".lobster/**/*events*.jsonl",
  ".lobster/**/*actions*.jsonl",
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

  if (basename === "commands.err.log") {
    return "openclaw-command-log";
  }

  if (
    basename === "gateway.log" ||
    basename === "gateway.err.log" ||
    basename === "openclaw-gateway.log" ||
    basename === "claw-gateway.log" ||
    basename === "lobster-gateway.log" ||
    /^(openclaw|claw|lobster)-\d{4}-\d{2}-\d{2}\.log$/.test(basename)
  ) {
    return "openclaw-gateway-log";
  }

  return "generic-jsonl";
}

function inferClawRuntimeName(options: {
  feedPath?: string;
  targetRoot?: string;
  fallback?: string;
}): string {
  const candidates = [options.feedPath, options.targetRoot, options.fallback]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .map((value) => value.toLowerCase());

  if (candidates.some((value) => value.includes("lobster"))) {
    return "lobster";
  }

  if (
    candidates.some(
      (value) => value.includes(".claw") || /(^|[\\/])claw([\\/]|$)/.test(value)
    )
  ) {
    return "claw";
  }

  return options.fallback?.trim() || "openclaw";
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

  if (/(delete|deleting|remove|removing|rm|unlink|wipe|wiping|purge)/.test(normalized)) {
    return "delete-files";
  }

  if (
    /(write|writing|modify|modifying|edit|editing|update|updating|rename|renaming|move|moving|copy|copying)/.test(normalized) &&
    /(file|files|fs|disk|path|workspace)/.test(normalized)
  ) {
    return "modify-files";
  }

  if (/(payment|paying|purchase|purchasing|checkout|checking out|order|ordering|stripe|paypal|wallet)/.test(normalized)) {
    return "purchase-or-payment";
  }

  if (/(bank|banking|finance|financial|broker|trade|trading|portfolio|account-balance)/.test(normalized)) {
    return "bank-access";
  }

  if (/(secret|secrets|token|tokens|credential|credentials|password|passwords|key|keys)/.test(normalized)) {
    return "sensitive-secret-access";
  }

  if (/(sensitive|private|customer-data|customer data|pii|record|records|dataset|datasets)/.test(normalized)) {
    return "sensitive-data-access";
  }

  if (/(publish|post|tweet|social|tiktok|youtube|linkedin|reddit)/.test(normalized)) {
    return "public-post";
  }

  if (/(message|whatsapp|telegram|slack|discord|wechat)/.test(normalized)) {
    return "send-message";
  }

  return undefined;
}

function inferStatusFromMessage(message: string): AuditEvent["status"] {
  const normalized = message.trim().toLowerCase();

  if (
    /(attempt|attempting|trying|starting|about to|preparing to|sending|posting|publishing|deleting|removing|wiping|reading|accessing|writing|modifying|updating|charging|paying|purchasing|checking out)/.test(
      normalized
    )
  ) {
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

function inferRecipientFromText(message: string): string | undefined {
  const naturalHandleOrPhoneMatch = message.match(
    /\bto\s+(@[A-Za-z0-9_.-]+|#[A-Za-z0-9_.-]+|\+\d[\d\s-]{6,}\d)\b/i
  );
  if (naturalHandleOrPhoneMatch?.[1]) {
    return naturalHandleOrPhoneMatch[1].replace(/\s+/g, " ").trim();
  }

  const handleOrPhoneMatch = message.match(
    /\b(?:to|recipient|chat|room|channel|thread|dm|handle|user)\s*[:=]\s*("?)(@[A-Za-z0-9_.-]+|#[A-Za-z0-9_.-]+|\+\d[\d\s-]{6,}\d|[A-Za-z0-9_.-]{3,})\1/i
  );
  if (handleOrPhoneMatch?.[2]) {
    return handleOrPhoneMatch[2].replace(/\s+/g, " ").trim();
  }

  const labeledMatch = message.match(
    /\b(?:to|recipient|email|mail_to|mailto)\s*[:=]\s*("?)([A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\1/i
  );
  if (labeledMatch?.[2]) {
    return labeledMatch[2];
  }

  const emailMatch = message.match(/\b([A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/);
  if (emailMatch?.[1]) {
    return emailMatch[1];
  }

  return undefined;
}

function inferUrlFromText(message: string): string | undefined {
  const match = message.match(/\bhttps?:\/\/[^\s)"']+/i);
  return match?.[0];
}

function inferSocialPlatformFromText(message: string): string | undefined {
  const normalized = message.toLowerCase();

  if (/\btiktok\b/.test(normalized)) return "TikTok";
  if (/\b(?:twitter|tweeting|tweeted)\b/.test(normalized)) return "X";
  if (/\bx\b/.test(normalized) && /\b(?:post|posting|publish|publishing)\b/.test(normalized)) {
    return "X";
  }
  if (/\byoutube\b/.test(normalized)) return "YouTube";
  if (/\blinkedin\b/.test(normalized)) return "LinkedIn";
  if (/\breddit\b/.test(normalized)) return "Reddit";
  if (/\binstagram\b/.test(normalized)) return "Instagram";
  return undefined;
}

function inferSocialAccountFromText(message: string): string | undefined {
  const labeledMatch = message.match(
    /\b(?:account|channel|handle|profile)\s*[:=]?\s*("?)(@[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]{3,})\1/i
  );
  if (labeledMatch?.[2]) {
    return labeledMatch[2];
  }

  const naturalMatch = message.match(
    /\b(?:to|on|via)\s+(?:twitter|x|tiktok|youtube|linkedin|reddit|instagram)\s+(?:account|channel|handle|profile)\s+(@?[A-Za-z0-9_.-]{3,})/i
  );
  if (naturalMatch?.[1]) {
    return naturalMatch[1];
  }

  return undefined;
}

function inferSecretNameFromText(message: string): string | undefined {
  const labeledMatch = message.match(
    /\b(?:secret|token|credential|password|key)\s*[:=]\s*("?)([A-Z][A-Z0-9_]{2,})\1/
  );
  if (labeledMatch?.[2]) {
    return labeledMatch[2];
  }

  const bareMatch = message.match(/\b([A-Z][A-Z0-9_]{2,}(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*)\b/);
  if (bareMatch?.[1]) {
    return bareMatch[1];
  }

  return undefined;
}

function inferAccountLabelFromText(message: string): string | undefined {
  const ibanMatch = message.match(/\b([A-Z]{2}\d{2}[A-Z0-9]{8,30})\b/);
  if (ibanMatch?.[1]) {
    return `bank account ${ibanMatch[1]}`;
  }

  const invoiceMatch = message.match(/\b(invoice|order)\s+([A-Za-z0-9_-]+)/i);
  if (invoiceMatch?.[0]) {
    return invoiceMatch[0];
  }

  const merchantMatch = message.match(/\bmerchant\s*[:=]?\s*([A-Za-z0-9_.-]+)/i);
  if (merchantMatch?.[1]) {
    return `merchant ${merchantMatch[1]}`;
  }

  const accountMatch = message.match(
    /\b(account|portfolio|wallet|card)\b\s*[:=]?\s*([A-Za-z0-9_.-]+)/i
  );
  if (accountMatch?.[0]) {
    return accountMatch[0];
  }

  const bankingOverviewMatch = message.match(/\bbank(?:ing)?\s+account\s+[A-Za-z0-9_.-]+/i);
  if (bankingOverviewMatch?.[0]) {
    return bankingOverviewMatch[0];
  }

  return undefined;
}

function inferSensitiveDataLabelFromText(message: string): string | undefined {
  const datasetMatch = message.match(
    /\b(?:dataset|table|records?|customer-data|customer data|pii|document)\s*[:=]?\s*([A-Za-z0-9_.-]+\.(?:csv|json|jsonl|parquet|xlsx|tsv)|[A-Za-z0-9_.-]{3,})/i
  );
  if (datasetMatch?.[1]) {
    return datasetMatch[1];
  }

  const naturalDatasetMatch = message.match(
    /\b(?:reading|accessing|opening|loading)\s+(?:dataset|table|records?)\s+([A-Za-z0-9_.-]+\.(?:csv|json|jsonl|parquet|xlsx|tsv)|[A-Za-z0-9_.-]{3,})/i
  );
  if (naturalDatasetMatch?.[1]) {
    return naturalDatasetMatch[1];
  }

  const fileLikeMatch = message.match(
    /\b([A-Za-z0-9_.-]+\.(?:csv|json|jsonl|parquet|xlsx|tsv|db|sqlite))\b/i
  );
  if (fileLikeMatch?.[1]) {
    return fileLikeMatch[1];
  }

  return undefined;
}

function inferSpecificTargetPathFromText(
  message: string,
  targetRoot: string
): string | undefined {
  const targetMatch = message.match(
    /\b(?:path|file|target|resource)\s*[:=]\s*("?)([^"\s)]+)\1/i
  );

  if (!targetMatch?.[2]) {
    return undefined;
  }

  return path.resolve(targetRoot, targetMatch[2]);
}

function inferTargetFromText(message: string, targetRoot: string): string {
  const specificTarget = inferSpecificTargetPathFromText(message, targetRoot);
  if (!specificTarget) {
    return targetRoot;
  }

  return specificTarget;
}

function isFileLikeAction(action?: string): boolean {
  return /(delete|remove|modify|write|edit|copy|move|file)/i.test(action ?? "");
}

export function buildActionEvidenceFromText(
  message: string,
  targetRoot: string,
  baseEvidence: Record<string, unknown> = {},
  action?: string
): Record<string, unknown> {
  const evidence: Record<string, unknown> = { ...baseEvidence };
  const recipient = inferRecipientFromText(message);
  const filePath = inferSpecificTargetPathFromText(message, targetRoot);
  const url = inferUrlFromText(message);
  const secretName = inferSecretNameFromText(message);
  const accountLabel = inferAccountLabelFromText(message);
  const sensitiveDataLabel = inferSensitiveDataLabelFromText(message);
  const socialPlatform = inferSocialPlatformFromText(message);
  const socialAccount = inferSocialAccountFromText(message);

  if (recipient) {
    evidence.recipient = recipient;
  }

  if (filePath) {
    if (isFileLikeAction(action)) {
      evidence.filePath = filePath;
    } else if (typeof evidence.resourceLabel !== "string") {
      evidence.resourceLabel = filePath;
    }
  }

  if (url) {
    evidence.url = url;
  }

  if (secretName) {
    evidence.secretName = secretName;
  }

  if (accountLabel) {
    evidence.accountLabel = accountLabel;
  }

  if (sensitiveDataLabel) {
    evidence.sensitiveDataLabel = sensitiveDataLabel;
  }

  if (socialPlatform) {
    evidence.platform = socialPlatform;
  }

  if (socialAccount) {
    evidence.socialAccount = socialAccount;
  }

  return evidence;
}

function buildActionEvidenceFromStructuredPayload(options: {
  parsed: Record<string, unknown>;
  targetRoot: string;
  message?: string;
  targetValue?: string;
  action?: string;
  baseEvidence?: Record<string, unknown>;
}): Record<string, unknown> {
  const serialized = JSON.stringify(options.parsed);
  const evidence = buildActionEvidenceFromText(
    options.message ?? "",
    options.targetRoot,
    options.baseEvidence,
    options.action
  );

  const recipient =
    pickString(options.parsed, [
      "recipient",
      "to",
      "email",
      ["input", "recipient"],
      ["input", "to"],
      ["input", "email"],
      ["response", "output", "0", "input", "recipient"],
      ["response", "output", "0", "input", "to"],
      ["response", "output", "0", "input", "email"],
      ["response", "output", "0", "arguments", "recipient"],
      ["response", "output", "0", "arguments", "to"],
      ["response", "output", "0", "arguments", "email"],
      ["content", "0", "input", "recipient"],
      ["content", "0", "input", "to"],
      ["content", "0", "input", "email"],
      ["content", "0", "arguments", "recipient"],
      ["content", "0", "arguments", "to"],
      ["content", "0", "arguments", "email"],
      ["item", "input", "recipient"],
      ["item", "input", "to"],
      ["item", "input", "email"],
      ["item", "arguments", "recipient"],
      ["item", "arguments", "to"],
      ["item", "arguments", "email"],
      ["content_block", "input", "recipient"],
      ["content_block", "input", "to"],
      ["content_block", "input", "email"],
      ["args", "recipient"],
      ["args", "to"],
      ["args", "email"],
      ["arguments", "recipient"],
      ["arguments", "to"],
      ["arguments", "email"],
      ["tool", "input", "recipient"],
      ["tool", "input", "to"],
      ["tool", "input", "email"],
      ["params", "recipient"],
      ["params", "to"],
      ["data", "recipient"],
      ["data", "to"],
      ["data", "input", "recipient"],
      ["data", "input", "to"],
      ["data", "args", "recipient"],
      ["data", "args", "to"],
      ["data", "arguments", "recipient"],
      ["data", "arguments", "to"],
      ["payload", "recipient"],
      ["payload", "to"],
      ["payload", "input", "recipient"],
      ["payload", "input", "to"],
      ["payload", "args", "recipient"],
      ["payload", "args", "to"],
      ["payload", "arguments", "recipient"],
      ["payload", "arguments", "to"],
      ["event", "recipient"],
      ["event", "to"],
      ["event", "input", "recipient"],
      ["event", "input", "to"],
      ["event", "args", "recipient"],
      ["event", "args", "to"],
      ["event", "arguments", "recipient"],
      ["event", "arguments", "to"]
    ]) ??
    inferRecipientFromText(serialized) ??
    undefined;
  const url =
    pickString(options.parsed, [
      "url",
      "link",
      ["input", "url"],
      ["input", "link"],
      ["response", "output", "0", "input", "url"],
      ["response", "output", "0", "arguments", "url"],
      ["content", "0", "input", "url"],
      ["content", "0", "arguments", "url"],
      ["item", "input", "url"],
      ["item", "input", "link"],
      ["item", "arguments", "url"],
      ["item", "arguments", "link"],
      ["content_block", "input", "url"],
      ["content_block", "input", "link"],
      ["args", "url"],
      ["args", "link"],
      ["arguments", "url"],
      ["arguments", "link"],
      ["params", "url"],
      ["data", "input", "url"],
      ["data", "args", "url"],
      ["data", "arguments", "url"],
      ["data", "url"],
      ["event", "input", "url"],
      ["event", "args", "url"],
      ["event", "arguments", "url"],
      ["payload", "url"]
    ]) ??
    inferUrlFromText(serialized) ??
    undefined;
  const secretName =
    pickString(options.parsed, [
      "secret",
      "secretName",
      "tokenName",
      ["input", "secret"],
      ["input", "secretName"],
      ["response", "output", "0", "input", "secret"],
      ["response", "output", "0", "input", "secretName"],
      ["response", "output", "0", "arguments", "secret"],
      ["response", "output", "0", "arguments", "secretName"],
      ["content", "0", "input", "secret"],
      ["content", "0", "input", "secretName"],
      ["content", "0", "arguments", "secret"],
      ["content", "0", "arguments", "secretName"],
      ["item", "input", "secret"],
      ["item", "input", "secretName"],
      ["item", "arguments", "secret"],
      ["item", "arguments", "secretName"],
      ["content_block", "input", "secret"],
      ["content_block", "input", "secretName"],
      ["args", "secret"],
      ["args", "secretName"],
      ["arguments", "secret"],
      ["arguments", "secretName"],
      ["params", "secret"],
      ["data", "input", "secret"],
      ["data", "input", "secretName"],
      ["data", "args", "secret"],
      ["data", "args", "secretName"],
      ["data", "arguments", "secret"],
      ["data", "arguments", "secretName"],
      ["data", "secret"],
      ["event", "input", "secret"],
      ["event", "input", "secretName"],
      ["event", "args", "secret"],
      ["event", "args", "secretName"],
      ["event", "arguments", "secret"],
      ["event", "arguments", "secretName"],
      ["payload", "secret"]
    ]) ??
    inferSecretNameFromText(serialized) ??
    undefined;
  const accountLabel =
    pickString(options.parsed, [
      "account",
      "accountId",
      "invoice",
      "orderId",
      "merchant",
      ["input", "account"],
      ["input", "accountId"],
      ["input", "invoice"],
      ["input", "orderId"],
      ["input", "merchant"],
      ["response", "output", "0", "input", "account"],
      ["response", "output", "0", "input", "accountId"],
      ["response", "output", "0", "input", "invoice"],
      ["response", "output", "0", "input", "orderId"],
      ["response", "output", "0", "input", "merchant"],
      ["response", "output", "0", "arguments", "account"],
      ["response", "output", "0", "arguments", "accountId"],
      ["response", "output", "0", "arguments", "invoice"],
      ["response", "output", "0", "arguments", "orderId"],
      ["response", "output", "0", "arguments", "merchant"],
      ["content", "0", "input", "account"],
      ["content", "0", "input", "accountId"],
      ["content", "0", "input", "invoice"],
      ["content", "0", "input", "orderId"],
      ["content", "0", "input", "merchant"],
      ["content", "0", "arguments", "account"],
      ["content", "0", "arguments", "accountId"],
      ["content", "0", "arguments", "invoice"],
      ["content", "0", "arguments", "orderId"],
      ["content", "0", "arguments", "merchant"],
      ["item", "input", "account"],
      ["item", "input", "accountId"],
      ["item", "input", "invoice"],
      ["item", "input", "orderId"],
      ["item", "input", "merchant"],
      ["item", "arguments", "account"],
      ["item", "arguments", "accountId"],
      ["item", "arguments", "invoice"],
      ["item", "arguments", "orderId"],
      ["item", "arguments", "merchant"],
      ["content_block", "input", "account"],
      ["content_block", "input", "accountId"],
      ["content_block", "input", "invoice"],
      ["content_block", "input", "orderId"],
      ["content_block", "input", "merchant"],
      ["args", "account"],
      ["args", "accountId"],
      ["args", "invoice"],
      ["args", "orderId"],
      ["args", "merchant"],
      ["arguments", "account"],
      ["arguments", "accountId"],
      ["arguments", "invoice"],
      ["arguments", "orderId"],
      ["arguments", "merchant"],
      ["params", "account"],
      ["params", "invoice"],
      ["params", "orderId"],
      ["data", "input", "account"],
      ["data", "input", "accountId"],
      ["data", "input", "invoice"],
      ["data", "input", "orderId"],
      ["data", "args", "account"],
      ["data", "args", "invoice"],
      ["data", "args", "orderId"],
      ["data", "arguments", "account"],
      ["data", "arguments", "invoice"],
      ["data", "arguments", "orderId"],
      ["data", "account"],
      ["data", "invoice"],
      ["data", "orderId"],
      ["event", "input", "account"],
      ["event", "input", "accountId"],
      ["event", "input", "invoice"],
      ["event", "input", "orderId"],
      ["event", "args", "account"],
      ["event", "args", "invoice"],
      ["event", "args", "orderId"],
      ["event", "arguments", "account"],
      ["event", "arguments", "invoice"],
      ["event", "arguments", "orderId"],
      ["payload", "account"],
      ["payload", "invoice"],
      ["payload", "orderId"]
    ]) ??
    inferAccountLabelFromText(serialized) ??
    undefined;
  const sensitiveDataLabel =
    pickString(options.parsed, [
      "dataset",
      "table",
      "recordSet",
      "document",
      ["input", "dataset"],
      ["input", "table"],
      ["input", "document"],
      ["response", "output", "0", "input", "dataset"],
      ["response", "output", "0", "input", "table"],
      ["response", "output", "0", "input", "document"],
      ["response", "output", "0", "arguments", "dataset"],
      ["response", "output", "0", "arguments", "table"],
      ["response", "output", "0", "arguments", "document"],
      ["content", "0", "input", "dataset"],
      ["content", "0", "input", "table"],
      ["content", "0", "input", "document"],
      ["content", "0", "arguments", "dataset"],
      ["content", "0", "arguments", "table"],
      ["content", "0", "arguments", "document"],
      ["item", "input", "dataset"],
      ["item", "input", "table"],
      ["item", "input", "document"],
      ["item", "arguments", "dataset"],
      ["item", "arguments", "table"],
      ["item", "arguments", "document"],
      ["content_block", "input", "dataset"],
      ["content_block", "input", "table"],
      ["content_block", "input", "document"],
      ["args", "dataset"],
      ["args", "table"],
      ["args", "document"],
      ["arguments", "dataset"],
      ["arguments", "table"],
      ["arguments", "document"],
      ["params", "dataset"],
      ["params", "table"],
      ["params", "document"],
      ["data", "input", "dataset"],
      ["data", "input", "table"],
      ["data", "input", "document"],
      ["data", "args", "dataset"],
      ["data", "args", "table"],
      ["data", "args", "document"],
      ["data", "arguments", "dataset"],
      ["data", "arguments", "table"],
      ["data", "arguments", "document"],
      ["data", "dataset"],
      ["data", "table"],
      ["data", "document"],
      ["event", "input", "dataset"],
      ["event", "input", "table"],
      ["event", "input", "document"],
      ["event", "args", "dataset"],
      ["event", "args", "table"],
      ["event", "args", "document"],
      ["event", "arguments", "dataset"],
      ["event", "arguments", "table"],
      ["event", "arguments", "document"],
      ["payload", "dataset"],
      ["payload", "table"],
      ["payload", "document"]
    ]) ??
    inferSensitiveDataLabelFromText(serialized) ??
    undefined;

  if (recipient) {
    evidence.recipient = recipient;
  }

  if (options.targetValue) {
    const resolvedTarget = path.resolve(options.targetRoot, options.targetValue);
    if (isFileLikeAction(options.action)) {
      evidence.filePath = resolvedTarget;
    } else if (typeof evidence.resourceLabel !== "string") {
      evidence.resourceLabel = options.targetValue;
    }
  }

  if (url) {
    evidence.url = url;
  }

  if (secretName) {
    evidence.secretName = secretName;
  }

  if (accountLabel) {
    evidence.accountLabel = accountLabel;
  }

  if (sensitiveDataLabel) {
    evidence.sensitiveDataLabel = sensitiveDataLabel;
  }

  return evidence;
}

function looksLikeStructuredToolEvent(method?: string): boolean {
  if (typeof method !== "string" || method.trim().length === 0) {
    return false;
  }

  return /(tools\/call|tools\/result|tools\/error|tool.call|tool.result|tool.error|tool-call|tool-result|tool-error|toolCall|toolResult|toolError|mcp.tool.call|mcp.tool.result|mcp.tool.error|tool_use|tool_result|tool_error|tool-use|tool-result|tool-error|tool use|tool result|tool error|toolUse|toolResult|toolError|mcp.tool_use|mcp.tool_result|mcp.tool_error|function_call|function.call|function-call|function call)/i.test(
    method
  );
}

type ParsedPlainTextLogLine = {
  timestampValue?: string;
  levelValue?: string;
  scopeValue?: string;
  message: string;
};

function parsePlainTextLogLine(line: string): ParsedPlainTextLogLine {
  const trimmed = line.trim();
  const textMatch =
    trimmed.match(
      /^(?<timestamp>\d{4}-\d{2}-\d{2}[T ][^ ]+)\s+(?<level>[A-Z]+)\s+(?<scope>[A-Za-z0-9_.-]+)[:\s-]+(?<message>.+)$/i
    ) ??
    trimmed.match(
      /^\[(?<timestamp>[^\]]+)\]\s+(?<level>[A-Z]+)\s+(?<scope>[A-Za-z0-9_.-]+)[:\s-]+(?<message>.+)$/i
    );

  if (!textMatch) {
    return { message: trimmed };
  }

  return {
    timestampValue: textMatch.groups?.timestamp?.trim(),
    levelValue: textMatch.groups?.level?.trim(),
    scopeValue: textMatch.groups?.scope?.trim(),
    message: textMatch.groups?.message?.trim() ?? trimmed
  };
}

function parsePlainTextMcpToolCallLine(line: string, targetRoot: string): AuditEvent | null {
  const trimmed = line.trim();
  if (!trimmed) {
    return null;
  }

  const { timestampValue, levelValue, scopeValue, message } = parsePlainTextLogLine(trimmed);
  const normalizedMessage = message.toLowerCase();

  if (
    !/(tools\/call|tools\/result|tools\/error|tool\s+call|tool\s+result|tool\s+error|tool-call|tool-result|tool-error|mcp\s+tool|calling\s+tool|invoking\s+tool|completed\s+tool|finished\s+tool|failed\s+tool|error\s+tool)/i.test(
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
  const inferredStatus = inferStatusFromMessage(message);
  const status = inferredStatus === "observed" ? "attempted" : inferredStatus;

  let humanMessage: string;
  if (status === "succeeded") {
    humanMessage =
      toolName && toolName !== action
        ? `${runtimeName} 刚完成了一个 MCP 工具调用，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 刚完成了一个 MCP 工具调用，TraceRoot 判断这一步相当于：${humanAction}。`;
  } else if (status === "failed") {
    humanMessage =
      toolName && toolName !== action
        ? `${runtimeName} 刚尝试了一个 MCP 工具调用，但没有完成，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 刚尝试了一个 MCP 工具调用，但没有完成，TraceRoot 判断这一步相当于：${humanAction}。`;
  } else {
    humanMessage =
      toolName && toolName !== action
        ? `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}。`;
  }

  return {
    timestamp: timestampValue ?? new Date().toISOString(),
    severity,
    category: "action-event",
    source: "runtime-feed",
    target: inferTargetFromText(message, targetRoot),
    runtime: runtimeName,
    surfaceKind: "runtime",
    action,
    status,
    message: humanMessage,
    recommendation: inferRecommendation(action, severity),
    evidence: buildActionEvidenceFromText(message, targetRoot, {
      source: "mcp-tool-call-log",
      toolName,
      channel,
      sender,
      rawLine: trimmed
    }, action)
  };
}

function parseGenericPlainTextRuntimeActionLine(line: string, targetRoot: string): AuditEvent | null {
  const trimmed = line.trim();
  if (!trimmed) {
    return null;
  }

  const { timestampValue, levelValue, scopeValue, message } = parsePlainTextLogLine(trimmed);
  const action = inferActionFromText(message);
  if (!action) {
    return null;
  }

  const scopeNormalized = scopeValue?.trim().toLowerCase();
  const runtimeName =
    scopeValue &&
    !["tool", "tools", "mcp", "gateway", "runtime", "agent", "watcher"].includes(
      scopeNormalized ?? ""
    )
      ? scopeValue
      : "运行时";
  const severity = normalizeSeverity(levelValue) ?? severityFromAction(action);
  const channel = inferChannelFromText(message);
  const sender = inferSenderFromText(message);

  return {
    timestamp: timestampValue ?? new Date().toISOString(),
    severity,
    category: "action-event",
    source: "runtime-feed",
    target: inferTargetFromText(message, targetRoot),
    runtime: runtimeName,
    surfaceKind: "runtime",
    action,
    status: inferStatusFromMessage(message),
    message: `${runtimeName} 刚记录到：${message}`,
    recommendation: inferRecommendation(action, severity),
    evidence: buildActionEvidenceFromText(message, targetRoot, {
      source: "runtime-plain-text-log",
      scope: scopeValue,
      channel,
      sender,
      rawLine: trimmed
    }, action)
  };
}

function inferStructuredRuntimeFeedEvent(
  parsed: Record<string, unknown>,
  targetRoot: string
): AuditEvent | null {
  const method = pickString(parsed, [
    ["response", "output", "0", "type"],
    ["content", "0", "type"],
    ["item", "type"],
    ["content_block", "type"],
    ["event", "item", "type"],
    ["event", "content_block", "type"],
    ["data", "item", "type"],
    ["data", "content_block", "type"],
    ["payload", "item", "type"],
    ["payload", "content_block", "type"],
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
    "toolName",
    "tool_name",
    "name",
    ["response", "output", "0", "name"],
    ["content", "0", "name"],
    ["response", "output", "0", "tool", "name"],
    ["content", "0", "tool", "name"],
    ["tool", "name"],
    ["item", "name"],
    ["content_block", "name"],
    ["item", "tool", "name"],
    ["content_block", "tool", "name"],
    ["input", "toolName"],
    ["input", "tool_name"],
    ["args", "toolName"],
    ["args", "tool_name"],
    ["arguments", "toolName"],
    ["arguments", "tool_name"],
    ["params", "name"],
    ["params", "tool"],
    ["params", "toolName"],
    ["params", "tool_name"],
    ["event", "name"],
    ["event", "toolName"],
    ["event", "tool_name"],
    ["event", "item", "name"],
    ["event", "content_block", "name"],
    ["event", "tool", "name"],
    ["event", "input", "toolName"],
    ["event", "input", "tool_name"],
    ["event", "args", "toolName"],
    ["event", "args", "tool_name"],
    ["event", "arguments", "toolName"],
    ["event", "arguments", "tool_name"],
    ["event", "params", "name"],
    ["event", "params", "tool"],
    ["data", "name"],
    ["data", "toolName"],
    ["data", "tool_name"],
    ["data", "item", "name"],
    ["data", "content_block", "name"],
    ["data", "tool", "name"],
    ["data", "input", "toolName"],
    ["data", "input", "tool_name"],
    ["data", "args", "toolName"],
    ["data", "args", "tool_name"],
    ["data", "arguments", "toolName"],
    ["data", "arguments", "tool_name"],
    ["data", "params", "name"],
    ["data", "params", "tool"],
    ["payload", "name"],
    ["payload", "toolName"],
    ["payload", "tool_name"],
    ["payload", "item", "name"],
    ["payload", "content_block", "name"],
    ["payload", "tool", "name"],
    ["payload", "input", "toolName"],
    ["payload", "input", "tool_name"],
    ["payload", "args", "toolName"],
    ["payload", "args", "tool_name"],
    ["payload", "arguments", "toolName"],
    ["payload", "arguments", "tool_name"],
    ["payload", "params", "name"],
    ["payload", "params", "tool"]
  ]);

  const looksLikeToolCall = looksLikeStructuredToolEvent(method);

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
  const outerEventType = pickString(parsed, [
    "type",
    ["event", "type"],
    ["data", "type"],
    ["payload", "type"]
  ]);
  const status = explicitStatus
    ? normalizeStatus(explicitStatus)
    : hasError
      ? "failed"
      : hasResult
        ? "succeeded"
        : typeof outerEventType === "string" &&
            /(done|completed|finished|result|success|stop)$/i.test(outerEventType)
          ? "succeeded"
          : typeof outerEventType === "string" &&
              /(error|failed|failure)$/i.test(outerEventType)
            ? "failed"
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
    ["response", "output", "0", "input", "path"],
    ["response", "output", "0", "input", "file"],
    ["response", "output", "0", "input", "target"],
    ["response", "output", "0", "input", "resource"],
    ["response", "output", "0", "arguments", "path"],
    ["response", "output", "0", "arguments", "file"],
    ["response", "output", "0", "arguments", "target"],
    ["response", "output", "0", "arguments", "resource"],
    ["content", "0", "input", "path"],
    ["content", "0", "input", "file"],
    ["content", "0", "input", "target"],
    ["content", "0", "input", "resource"],
    ["content", "0", "arguments", "path"],
    ["content", "0", "arguments", "file"],
    ["content", "0", "arguments", "target"],
    ["content", "0", "arguments", "resource"],
    ["item", "input", "path"],
    ["item", "input", "file"],
    ["item", "input", "target"],
    ["item", "input", "resource"],
    ["item", "arguments", "path"],
    ["item", "arguments", "file"],
    ["item", "arguments", "target"],
    ["item", "arguments", "resource"],
    ["content_block", "input", "path"],
    ["content_block", "input", "file"],
    ["content_block", "input", "target"],
    ["content_block", "input", "resource"],
    ["input", "path"],
    ["input", "file"],
    ["input", "target"],
    ["input", "resource"],
    ["args", "path"],
    ["args", "file"],
    ["args", "target"],
    ["args", "resource"],
    ["arguments", "path"],
    ["arguments", "file"],
    ["arguments", "target"],
    ["arguments", "resource"],
    ["params", "path"],
    ["params", "file"],
    ["event", "input", "path"],
    ["event", "input", "file"],
    ["event", "input", "target"],
    ["event", "args", "path"],
    ["event", "args", "file"],
    ["event", "args", "target"],
    ["event", "arguments", "path"],
    ["event", "arguments", "file"],
    ["event", "arguments", "target"],
    ["data", "params", "path"],
    ["data", "params", "file"],
    ["data", "input", "path"],
    ["data", "input", "file"],
    ["data", "input", "target"],
    ["data", "args", "path"],
    ["data", "args", "file"],
    ["data", "args", "target"],
    ["data", "arguments", "path"],
    ["data", "arguments", "file"],
    ["data", "arguments", "target"],
    ["payload", "params", "path"],
    ["payload", "params", "file"],
    ["payload", "input", "path"],
    ["payload", "input", "file"],
    ["payload", "input", "target"],
    ["payload", "args", "path"],
    ["payload", "args", "file"],
    ["payload", "args", "target"],
    ["payload", "arguments", "path"],
    ["payload", "arguments", "file"],
    ["payload", "arguments", "target"]
  ]);
  const target = targetValue ? path.resolve(targetRoot, targetValue) : targetRoot;
  const serialized = JSON.stringify(parsed);
  const directRecipient =
    pickString(parsed, [
      "recipient",
      "to",
      "email",
      ["params", "recipient"],
      ["params", "to"],
      ["data", "recipient"],
      ["data", "to"],
      ["payload", "recipient"],
      ["payload", "to"]
    ]) ??
    inferRecipientFromText(serialized) ??
    undefined;
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

  let humanMessage: string;
  if (status === "succeeded") {
    humanMessage =
      toolName && toolName !== action
        ? `${runtimeName} 刚完成了一个 MCP 工具调用，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 刚完成了一个 MCP 工具调用，TraceRoot 判断这一步相当于：${humanAction}。`;
  } else if (status === "failed") {
    humanMessage =
      toolName && toolName !== action
        ? `${runtimeName} 刚尝试了一个 MCP 工具调用，但没有完成，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 刚尝试了一个 MCP 工具调用，但没有完成，TraceRoot 判断这一步相当于：${humanAction}。`;
  } else {
    humanMessage =
      toolName && toolName !== action
        ? `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}（工具名：${toolLabel}）。`
        : `${runtimeName} 正在调用一个 MCP 工具，TraceRoot 判断这一步相当于：${humanAction}。`;
  }

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
    message: humanMessage,
    recommendation: inferRecommendation(action, severity),
    evidence: buildActionEvidenceFromStructuredPayload({
      parsed,
      targetRoot,
      targetValue,
      action,
      baseEvidence: {
        source: "mcp-tool-call",
        method,
        toolName,
        channel,
        sender,
        sessionKey,
        recipient: directRecipient,
        resourceLabel: !isFileLikeAction(action) && targetValue ? targetValue : undefined,
        raw: parsed
      }
    })
  };
}

function parseOpenClawCommandLogLine(
  line: string,
  targetRoot: string,
  feedPath?: string
): AuditEvent | null {
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

  const runtimeName = inferClawRuntimeName({
    feedPath,
    targetRoot,
    fallback: "openclaw"
  });
  const runtimeTitle =
    runtimeName === "lobster" ? "Lobster" : runtimeName === "claw" ? "Claw" : "OpenClaw";

  let message = `${runtimeTitle} 刚收到一个控制命令：${action}。`;
  if (normalized === "new") {
    message = `${runtimeTitle} 刚收到一个新任务启动命令（来源：${sourceChannel}）。`;
  } else if (normalized === "stop") {
    message = `${runtimeTitle} 刚收到一个停止命令（来源：${sourceChannel}）。`;
  } else if (normalized === "resume") {
    message = `${runtimeTitle} 刚收到一个恢复运行命令（来源：${sourceChannel}）。`;
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
    runtime: runtimeName,
    surfaceKind: "runtime",
    action: `openclaw-command-${normalized}`,
    status: "observed",
    message,
    evidence: buildActionEvidenceFromStructuredPayload({
      parsed,
      targetRoot,
      message,
      action: `openclaw-command-${normalized}`,
      baseEvidence: {
      source: "openclaw-command-logger",
      sessionKey,
      channel: sourceChannel,
      sender,
      raw: parsed
      }
    })
  };
}

function parseOpenClawGatewayLogLine(
  line: string,
  targetRoot: string,
  feedPath?: string
): AuditEvent | null {
  const plainTextEvent = parseOpenClawGatewayTextLine(line, targetRoot, feedPath);
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
  const runtimeName =
    pickString(parsed, ["runtime", "service"]) ??
    inferClawRuntimeName({ feedPath, targetRoot, fallback: "openclaw" });
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
    evidence: buildActionEvidenceFromStructuredPayload({
      parsed,
      targetRoot,
      message,
      targetValue,
      action,
      baseEvidence: {
      source: "openclaw-gateway-log",
      subsystem,
      channel,
      sender,
      sessionKey,
      raw: parsed
      }
    })
  };
}

function parseOpenClawGatewayTextLine(
  line: string,
  targetRoot: string,
  feedPath?: string
): AuditEvent | null {
  const trimmed = line.trim();
  if (!trimmed) {
    return null;
  }

  const { timestampValue, levelValue, scopeValue, message } = parsePlainTextLogLine(trimmed);
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
    runtime: inferClawRuntimeName({ feedPath, targetRoot, fallback: "openclaw" }),
    surfaceKind: "runtime",
    action,
    status: inferStatusFromMessage(message),
    message: `${inferClawRuntimeName({ feedPath, targetRoot, fallback: "openclaw" })} 刚提到：${message}`,
    recommendation: inferRecommendation(action, severity),
    evidence: buildActionEvidenceFromText(message, targetRoot, {
      source: "openclaw-gateway-log",
      subsystem: scopeValue,
      channel,
      sender,
      rawLine: trimmed
    }, action)
  };
}

function parseRuntimeFeedEvent(
  line: string,
  targetRoot: string,
  feedKind: RuntimeEventFeed["kind"] = "generic-jsonl",
  feedPath?: string
): AuditEvent | null {
  if (feedKind === "openclaw-command-log") {
    return parseOpenClawCommandLogLine(line, targetRoot, feedPath);
  }

  if (feedKind === "openclaw-gateway-log") {
    return parseOpenClawGatewayLogLine(line, targetRoot, feedPath);
  }

  let parsed: Record<string, unknown> | unknown[];

  try {
    parsed = JSON.parse(line) as Record<string, unknown> | unknown[];
  } catch {
    return (
      parsePlainTextMcpToolCallLine(line, targetRoot) ??
      parseGenericPlainTextRuntimeActionLine(line, targetRoot)
    );
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

  const message = pickString(parsed, [
    "message",
    "summary",
    "text",
    ["event", "message"],
    ["data", "message"],
    ["data", "summary"],
    ["payload", "message"],
    ["payload", "summary"]
  ]);

  const action =
    pickString(parsed, [
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
    ]) ?? inferActionFromText(message ?? "");

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
  const displayMessage = message ?? inferMessage(action, status, runtimeName);
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
    message: displayMessage,
    recommendation,
    evidence: buildActionEvidenceFromStructuredPayload({
      parsed,
      targetRoot,
      message: displayMessage,
      targetValue,
      action,
      baseEvidence: {
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
    })
  };
}

type CompanionFeed = {
  absolutePath: string;
  kind: RuntimeEventFeed["kind"];
};

function clawFamilyDefaultTempLogDirs(): string[] {
  const tempRoot =
    process.env.TMPDIR?.trim() ||
    process.env.TEMP?.trim() ||
    process.env.TMP?.trim() ||
    os.tmpdir();

  return clawFamilyNames.map((name) => path.join(tempRoot, name));
}

async function discoverDefaultOpenClawTempFeeds(): Promise<CompanionFeed[]> {
  const companionMap = new Map<string, CompanionFeed>();
  for (const tempLogDir of clawFamilyDefaultTempLogDirs()) {
    const globMatches = await fg(path.join(tempLogDir, "*-*.log"), {
      absolute: true,
      onlyFiles: true,
      unique: true
    });

    for (const matchedPath of globMatches) {
      companionMap.set(matchedPath, {
        absolutePath: matchedPath,
        kind: classifyFeedKind(matchedPath)
      });
    }

    for (const filename of ["gateway.log", "gateway.err.log", "commands.log", "commands.err.log"]) {
      const candidatePath = path.join(tempLogDir, filename);

      try {
        const feedStats = await stat(candidatePath);
        if (!feedStats.isFile()) {
          continue;
        }
      } catch {
        continue;
      }

      companionMap.set(candidatePath, {
        absolutePath: candidatePath,
        kind: classifyFeedKind(candidatePath)
      });
    }
  }

  return [...companionMap.values()];
}

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
    rootName.startsWith(".openclaw") ||
    rootName.startsWith(".lobster") ||
    rootName.includes("openclaw") ||
    rootName.includes("lobster") ||
    rootName === "claw";
  const candidates = new Map<string, CompanionFeed>();
  let hasOpenClawConfig = false;

  for (const configName of [
    "openclaw.json",
    "openclaw.yaml",
    "openclaw.yml",
    "claw.json",
    "claw.yaml",
    "claw.yml",
    "lobster.json",
    "lobster.yaml",
    "lobster.yml"
  ]) {
    try {
      const configRaw = await readFile(path.join(targetRoot, configName), "utf8");
      const config =
        configName.endsWith(".json")
          ? (JSON5.parse(configRaw) as Record<string, unknown>)
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
    const defaultLogs = await discoverDefaultOpenClawTempFeeds();

    for (const feed of defaultLogs) {
      candidates.set(feed.absolutePath, {
        absolutePath: feed.absolutePath,
        kind: feed.kind
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
          ? (JSON5.parse(configRaw) as Record<string, unknown>)
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

export async function discoverHostNativeRuntimeFeeds(homeDir: string): Promise<{
  feeds: RuntimeEventFeed[];
  watchedRoots: NativeRuntimeFeedRoot[];
}> {
  const defaultTempRoots = clawFamilyDefaultTempLogDirs();
  const defaultTempRoot = defaultTempRoots[0] ?? path.join(os.tmpdir(), "openclaw");
  const defaultFeeds = await discoverDefaultOpenClawTempFeeds();

  if (defaultFeeds.length === 0) {
    return {
      feeds: [],
      watchedRoots: []
    };
  }

  const preferredRootCandidates = [
    path.join(homeDir, ".openclaw"),
    path.join(homeDir, ".lobster"),
    path.join(homeDir, ".config", "openclaw"),
    path.join(homeDir, ".config", "lobster"),
    path.join(homeDir, ".config", "claw"),
    ...(process.platform === "darwin"
      ? [
          path.join(homeDir, "Library", "Application Support", "OpenClaw"),
          path.join(homeDir, "Library", "Application Support", "Lobster"),
          path.join(homeDir, "Library", "Application Support", "Claw")
        ]
      : []),
    path.join(homeDir, "AppData", "Roaming", "OpenClaw"),
    path.join(homeDir, "AppData", "Roaming", "Lobster"),
    path.join(homeDir, "AppData", "Roaming", "Claw"),
    path.join(homeDir, "AppData", "Local", "OpenClaw"),
    path.join(homeDir, "AppData", "Local", "Lobster"),
    path.join(homeDir, "AppData", "Local", "Claw"),
    ...defaultTempRoots
  ];
  let rootDir = defaultTempRoot;

  for (const candidateRoot of preferredRootCandidates) {
    try {
      if ((await stat(candidateRoot)).isDirectory()) {
        rootDir = candidateRoot;
        break;
      }
    } catch {
      continue;
    }
  }

  const feeds = await Promise.all(
    defaultFeeds.map(async (feed) => ({
      absolutePath: await canonicalFeedPath(feed.absolutePath),
      displayPath: displayUserPath(feed.absolutePath),
      rootDir,
      kind: feed.kind ?? classifyFeedKind(feed.absolutePath)
    }))
  );

  return {
    feeds,
    watchedRoots: [
      {
        absolutePath: rootDir,
        displayPath: `系统默认 OpenClaw 日志位点（${displayUserPath(rootDir)}）`
      }
    ]
  };
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
        feed.kind,
        feed.absolutePath
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
        feed.kind,
        feed.absolutePath
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
        feed.kind,
        feed.absolutePath
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
