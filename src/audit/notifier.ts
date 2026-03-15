import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { actionLabel, runtimeActorLabel, whyThisMatters } from "./presentation";
import type { AuditEvent, AuditSeverity } from "./types";
import { displayUserPath } from "../utils/paths";

const execFileAsync = promisify(execFile);

export const SUPPORTED_OPENCLAW_NOTIFY_CHANNELS = [
  "whatsapp",
  "telegram",
  "discord",
  "googlechat",
  "slack",
  "mattermost",
  "signal",
  "imessage",
  "msteams"
] as const;

export interface NotificationConfig {
  webhookUrl?: string;
  openclawChannel?: string;
  openclawTarget?: string;
  openclawAccount?: string;
  openclawBin?: string;
  cooldownSeconds?: number;
}

export interface ResolvedNotificationConfig {
  webhookUrl?: string;
  openclawChannel?: string;
  openclawTarget?: string;
  openclawAccount?: string;
  openclawBin: string;
  cooldownMs: number;
}

function normalizeWebhookUrl(value?: string): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function normalizeText(value?: string): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function severityLabel(severity: AuditSeverity): string {
  switch (severity) {
    case "critical":
      return "极高风险";
    case "high-risk":
      return "高风险";
    case "risky":
      return "有风险";
    case "safe":
    default:
      return "普通";
  }
}

function statusLabel(event: AuditEvent): string | undefined {
  switch (event.status) {
    case "attempted":
      return "正在尝试执行";
    case "succeeded":
      return "已经执行完成";
    case "failed":
      return "这次尝试没有完成";
    default:
      return undefined;
  }
}

function buildTextSummary(event: AuditEvent): string {
  const actor = runtimeActorLabel(event.runtime);
  const parts = [
    `TraceRoot 刚盯到一个${severityLabel(event.severity)}动作`,
    `是谁：${actor}`,
    `动作：${actionLabel(event.action)}`
  ];

  parts.push(`为什么值得现在看一眼：${whyThisMatters(event.action, event.severity)}`);

  if (event.target) {
    parts.push(`位置：${displayUserPath(event.target)}`);
  }

  const status = statusLabel(event);
  if (status) {
    parts.push(`状态：${status}`);
  }

  if (event.recommendation) {
    parts.push(`建议：${event.recommendation}`);
  }

  return parts.join("\n");
}

function buildChatRelayText(event: AuditEvent): string {
  const actor = runtimeActorLabel(event.runtime);
  const lines = [
    `${event.severity === "critical" ? "🚨" : event.severity === "high-risk" ? "🛑" : "⚠️"} TraceRoot 刚盯到一个${severityLabel(event.severity)}动作`,
    `是谁：${actor}`,
    `动作：${actionLabel(event.action)}`
  ];

  lines.push(`为什么值得现在看一眼：${whyThisMatters(event.action, event.severity)}`);

  if (event.target) {
    lines.push(`位置：${displayUserPath(event.target)}`);
  }

  const status = statusLabel(event);
  if (status) {
    lines.push(`状态：${status}`);
  }

  if (event.recommendation) {
    lines.push(`建议：${event.recommendation}`);
  }

  lines.push("本地审计时间线也已经同步更新了。");

  return lines.join("\n");
}

export function resolveNotificationConfig(
  config: NotificationConfig = {}
): ResolvedNotificationConfig {
  const envCooldown = Number.parseInt(
    process.env.TRACEROOT_NOTIFY_COOLDOWN_SECONDS ?? "",
    10
  );
  const cooldownSeconds =
    typeof config.cooldownSeconds === "number" && config.cooldownSeconds > 0
      ? config.cooldownSeconds
      : Number.isInteger(envCooldown) && envCooldown > 0
        ? envCooldown
        : 30;

  return {
    webhookUrl:
      normalizeWebhookUrl(config.webhookUrl) ??
      normalizeWebhookUrl(process.env.TRACEROOT_NOTIFY_WEBHOOK_URL),
    openclawChannel:
      normalizeText(config.openclawChannel) ??
      normalizeText(process.env.TRACEROOT_NOTIFY_CHANNEL),
    openclawTarget:
      normalizeText(config.openclawTarget) ??
      normalizeText(process.env.TRACEROOT_NOTIFY_TARGET),
    openclawAccount:
      normalizeText(config.openclawAccount) ??
      normalizeText(process.env.TRACEROOT_NOTIFY_ACCOUNT),
    openclawBin:
      normalizeText(config.openclawBin) ??
      normalizeText(process.env.TRACEROOT_NOTIFY_OPENCLAW_BIN) ??
      "openclaw",
    cooldownMs: cooldownSeconds * 1000
  };
}

export function hasWebhookNotification(config: ResolvedNotificationConfig): boolean {
  return typeof config.webhookUrl === "string" && config.webhookUrl.length > 0;
}

export function hasOpenClawChannelNotification(
  config: ResolvedNotificationConfig
): boolean {
  return (
    typeof config.openclawChannel === "string" &&
    config.openclawChannel.length > 0 &&
    typeof config.openclawTarget === "string" &&
    config.openclawTarget.length > 0
  );
}

export function hasNotificationChannel(config: ResolvedNotificationConfig): boolean {
  return hasWebhookNotification(config) || hasOpenClawChannelNotification(config);
}

export function validateNotificationConfig(
  config: ResolvedNotificationConfig
): string | undefined {
  if (config.openclawChannel && !config.openclawTarget) {
    return "如果你想把提醒发到聊天入口，请同时提供 `--notify-target`。";
  }

  if (config.openclawTarget && !config.openclawChannel) {
    return "如果你提供了 `--notify-target`，也请同时提供 `--notify-channel`。";
  }

  if (
    config.openclawChannel &&
    !SUPPORTED_OPENCLAW_NOTIFY_CHANNELS.includes(
      config.openclawChannel as (typeof SUPPORTED_OPENCLAW_NOTIFY_CHANNELS)[number]
    )
  ) {
    return `TraceRoot 目前支持把提醒发到这些 OpenClaw 聊天入口：${SUPPORTED_OPENCLAW_NOTIFY_CHANNELS.join("、")}。`;
  }

  return undefined;
}

export function buildWebhookPayload(event: AuditEvent): Record<string, unknown> {
  return {
    source: "traceroot-audit",
    type: "runtime-alert",
    timestamp: event.timestamp,
    severity: event.severity,
    title: `TraceRoot 刚盯到一个${severityLabel(event.severity)}动作`,
    summary: `Agent 刚刚触发了一个${severityLabel(event.severity)}动作：${actionLabel(event.action)}`,
    text: buildTextSummary(event),
    action: event.action ?? null,
    actionLabel: actionLabel(event.action),
    runtime: event.runtime ?? null,
    status: event.status ?? null,
    target: event.target ? displayUserPath(event.target) : null,
    message: event.message,
    recommendation: event.recommendation ?? null
  };
}

export async function sendWebhookNotification(
  event: AuditEvent,
  config: ResolvedNotificationConfig
): Promise<void> {
  if (!config.webhookUrl) {
    return;
  }

  const response = await fetch(config.webhookUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "user-agent": "traceroot-audit/0.2.0"
    },
    body: JSON.stringify(buildWebhookPayload(event))
  });

  if (!response.ok) {
    throw new Error(`Webhook returned ${response.status}`);
  }
}

export async function sendOpenClawChannelNotification(
  event: AuditEvent,
  config: ResolvedNotificationConfig
): Promise<void> {
  if (!hasOpenClawChannelNotification(config)) {
    return;
  }

  const args = [
    "message",
    "send",
    "--channel",
    config.openclawChannel!,
    "--target",
    config.openclawTarget!,
    "--message",
    buildChatRelayText(event)
  ];

  if (config.openclawAccount) {
    args.push("--account", config.openclawAccount);
  }

  try {
    await execFileAsync(config.openclawBin, args);
  } catch (error) {
    const message =
      error instanceof Error && error.message
        ? error.message
        : "unknown OpenClaw channel delivery error";
    throw new Error(`OpenClaw channel relay failed: ${message}`);
  }
}
