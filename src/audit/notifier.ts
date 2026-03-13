import { actionLabel } from "./presentation";
import type { AuditEvent, AuditSeverity } from "./types";
import { displayUserPath } from "../utils/paths";

export interface NotificationConfig {
  webhookUrl?: string;
  cooldownSeconds?: number;
}

export interface ResolvedNotificationConfig {
  webhookUrl?: string;
  cooldownMs: number;
}

function normalizeWebhookUrl(value?: string): string | undefined {
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
  const parts = [
    `TraceRoot 刚盯到一个${severityLabel(event.severity)}动作`,
    `动作：${actionLabel(event.action)}`
  ];

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
    cooldownMs: cooldownSeconds * 1000
  };
}

export function hasWebhookNotification(config: ResolvedNotificationConfig): boolean {
  return typeof config.webhookUrl === "string" && config.webhookUrl.length > 0;
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
