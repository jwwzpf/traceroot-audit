import type { AuditEvent, AuditSeverity } from "./types";
import { displayUserPath } from "../utils/paths";

export function actionLabel(action?: string): string {
  if (!action) {
    return "未知动作";
  }

  const normalized = action.trim().toLowerCase();

  switch (normalized) {
    case "send-email":
      return "对外发邮件";
    case "publish-or-send-message":
      return "对外发帖或发消息";
    case "delete-or-modify-files":
      return "删改本地文件";
    case "purchase-or-payment":
      return "付款或下单";
    case "finance-access":
      return "访问金融或交易数据";
    case "delete-files":
      return "删除本地文件";
    case "modify-files":
      return "修改本地文件";
    case "public-post":
      return "公开发帖";
    case "send-message":
      return "对外发消息";
    case "sensitive-secret-access":
      return "读取敏感 secret";
    case "bank-access":
      return "访问银行或支付账户";
    case "sensitive-data-access":
      return "读取敏感数据";
    case "openclaw-command-new":
      return "收到新任务指令";
    case "openclaw-command-stop":
      return "收到停止指令";
    case "openclaw-command-resume":
      return "收到恢复运行指令";
  }

  if (/(send|draft).*(email|mail)|(email|mail).*(send|draft)/.test(normalized)) {
    return "对外发邮件";
  }

  if (/(publish|publishing|post|posting|tweet|social|tiktok|youtube|linkedin|reddit)/.test(normalized)) {
    return "公开发帖";
  }

  if (/(delete|deleting|remove|removing|rm|unlink|wipe|wiping|purge)/.test(normalized)) {
    return "删除本地文件";
  }

  if (/(write|writing|modify|modifying|edit|editing|update|updating|rename|renaming|move|moving|copy|copying)/.test(normalized) && /(file|files|fs|disk|path|workspace)/.test(normalized)) {
    return "修改本地文件";
  }

  if (/(payment|paying|purchase|purchasing|checkout|checking out|order|ordering|stripe|paypal|wallet)/.test(normalized)) {
    return "付款或下单";
  }

  if (/(bank|banking|finance|financial|broker|trade|trading|portfolio|account-balance)/.test(normalized)) {
    return "访问银行或交易数据";
  }

  if (/(secret|secrets|token|tokens|credential|credentials|password|passwords|key|keys)/.test(normalized)) {
    return "读取敏感 secret";
  }

  if (/(sensitive|private|customer-data|customer data|pii|record|records|dataset|datasets)/.test(normalized)) {
    return "读取敏感数据";
  }

  if (/(message|whatsapp|telegram|slack|discord|wechat)/.test(normalized)) {
    return "对外发消息";
  }

  return action.replace(/^run-/, "运行 ").replace(/-/g, " ");
}

export function runtimeActorLabel(runtime?: string): string {
  const normalized = runtime?.trim().toLowerCase();

  if (!normalized) {
    return "这个 agent";
  }

  if (normalized === "openclaw") {
    return "OpenClaw 运行时";
  }

  if (normalized === "mcp") {
    return "MCP 服务";
  }

  return runtime!.trim();
}

export function notifyChannelLabel(channel?: string): string | undefined {
  const normalized = channel?.trim().toLowerCase();

  if (!normalized) {
    return undefined;
  }

  switch (normalized) {
    case "telegram":
      return "Telegram";
    case "whatsapp":
      return "WhatsApp";
    case "slack":
      return "Slack";
    case "discord":
      return "Discord";
    case "signal":
      return "Signal";
    case "imessage":
      return "iMessage";
    case "googlechat":
      return "Google Chat";
    case "mattermost":
      return "Mattermost";
    case "msteams":
      return "Microsoft Teams";
    case "wechat":
      return "WeChat";
    default:
      return channel?.trim();
  }
}

function looksLikeNotifyChannel(value?: string): boolean {
  const normalized = value?.trim().toLowerCase();

  return [
    "telegram",
    "whatsapp",
    "slack",
    "discord",
    "signal",
    "imessage",
    "googlechat",
    "mattermost",
    "msteams",
    "wechat"
  ].includes(normalized ?? "");
}

export function actionTriggerSourceLabel(event: AuditEvent): string | null {
  const evidence = event.evidence ?? {};
  const channelValue =
    typeof evidence.channel === "string" ? evidence.channel.trim() : "";
  const senderValue =
    typeof evidence.sender === "string" ? evidence.sender.trim() : "";
  const sourceValue =
    typeof evidence.source === "string" ? evidence.source.trim() : "";
  const channel = notifyChannelLabel(
    channelValue || (looksLikeNotifyChannel(sourceValue) ? sourceValue : undefined)
  );

  if (channel && senderValue) {
    return `${channel}（${senderValue}）`;
  }

  if (channel) {
    return channel;
  }

  if (senderValue) {
    return senderValue;
  }

  return null;
}

export function actionTriggerContext(event: AuditEvent): string | null {
  const sourceLabel = actionTriggerSourceLabel(event);

  if (!sourceLabel) {
    return null;
  }

  return `来自 ${sourceLabel}`;
}

export function actionTriggerSentence(event: AuditEvent): string | null {
  const sourceLabel = actionTriggerSourceLabel(event);

  if (!sourceLabel) {
    return null;
  }

  return `这一步是从 ${sourceLabel} 触发出来的`;
}

function normalizeDisplayText(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function truncateDisplayText(value: string, maxLength = 60): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}

function getNestedValue(source: unknown, pathSegments: string[]): unknown {
  let current = source;

  for (const segment of pathSegments) {
    if (!current || typeof current !== "object") {
      return undefined;
    }

    current = (current as Record<string, unknown>)[segment];
  }

  return current;
}

function pickEvidenceString(
  source: unknown,
  candidates: Array<string | string[]>
): string | undefined {
  if (!source || typeof source !== "object") {
    return undefined;
  }

  for (const candidate of candidates) {
    const value = Array.isArray(candidate)
      ? getNestedValue(source, candidate)
      : (source as Record<string, unknown>)[candidate];

    const normalized = normalizeDisplayText(value);
    if (normalized) {
      return normalized;
    }
  }

  return undefined;
}

function inferSubjectFromRawEvidence(event: AuditEvent): string | null {
  const raw =
    typeof event.evidence?.raw === "object" && event.evidence?.raw
      ? event.evidence.raw
      : undefined;

  const recipient =
    pickEvidenceString(raw, [
      "recipient",
      "to",
      "email",
      ["params", "recipient"],
      ["params", "to"],
      ["params", "email"],
      ["event", "recipient"],
      ["event", "to"],
      ["data", "recipient"],
      ["payload", "recipient"]
    ]) ??
    undefined;
  if (recipient) {
    return `发给 ${truncateDisplayText(recipient)}`;
  }

  const account =
    pickEvidenceString(raw, [
      "account",
      "accountId",
      "invoice",
      "orderId",
      "merchant",
      ["params", "account"],
      ["params", "invoice"],
      ["params", "orderId"],
      ["event", "account"],
      ["data", "account"],
      ["payload", "account"]
    ]) ?? undefined;
  if (account) {
    return truncateDisplayText(account);
  }

  const secret =
    pickEvidenceString(raw, [
      "secret",
      "secretName",
      "tokenName",
      ["params", "secret"],
      ["event", "secret"],
      ["data", "secret"],
      ["payload", "secret"]
    ]) ?? undefined;
  if (secret) {
    return `secret ${truncateDisplayText(secret)}`;
  }

  const url =
    pickEvidenceString(raw, [
      "url",
      "link",
      ["params", "url"],
      ["event", "url"],
      ["data", "url"],
      ["payload", "url"]
    ]) ?? undefined;
  if (url) {
    return truncateDisplayText(url, 72);
  }

  const resource =
    pickEvidenceString(raw, [
      "target",
      "path",
      "resource",
      "file",
      ["params", "path"],
      ["params", "target"],
      ["event", "path"],
      ["data", "path"],
      ["payload", "path"]
    ]) ?? undefined;
  if (resource) {
    return truncateDisplayText(resource);
  }

  if (
    event.target &&
    /(delete|remove|modify|write|edit|copy|move|file)/i.test(event.action ?? "")
  ) {
    return displayUserPath(event.target);
  }

  return null;
}

export function actionSubjectLabel(event: AuditEvent): string | null {
  const evidence = event.evidence ?? {};
  const normalizedAction = (event.action ?? "").trim().toLowerCase();
  const recipient = normalizeDisplayText(evidence.recipient);
  if (recipient) {
    return `发给 ${truncateDisplayText(recipient)}`;
  }

  const filePath = normalizeDisplayText(evidence.filePath);
  if (filePath) {
    return displayUserPath(filePath);
  }

  const url = normalizeDisplayText(evidence.url);
  if (url) {
    return truncateDisplayText(url, 72);
  }

  const resourceLabel = normalizeDisplayText(evidence.resourceLabel);
  const accountLabel = normalizeDisplayText(evidence.accountLabel);
  const secretName = normalizeDisplayText(evidence.secretName);

  if (
    /(bank-access|purchase-or-payment|finance-access)/.test(normalizedAction) &&
    resourceLabel
  ) {
    return truncateDisplayText(resourceLabel);
  }

  if (accountLabel) {
    return truncateDisplayText(accountLabel);
  }

  if (secretName) {
    return `secret ${truncateDisplayText(secretName)}`;
  }

  if (resourceLabel) {
    return truncateDisplayText(resourceLabel);
  }

  return inferSubjectFromRawEvidence(event);
}

export function actionObjectSentence(event: AuditEvent): string | null {
  const subject = actionSubjectLabel(event);
  if (!subject) {
    return null;
  }

  return `这一步看起来涉及：${subject}`;
}

export function actionLabelWithSubject(event: AuditEvent): string {
  const label = actionLabel(event.action);
  const subject = actionSubjectLabel(event);

  return subject ? `${label}（${subject}）` : label;
}

export function whyThisMatters(
  action?: string,
  severity: AuditSeverity = "risky"
): string {
  const normalized = (action ?? "").trim().toLowerCase();

  if (normalized === "send-email") {
    return "这类动作会真正把内容发到外部世界里，通常值得你马上看一眼。";
  }

  if (normalized === "public-post") {
    return "这类动作一旦发出去，就是公开可见的内容，最好及时确认。";
  }

  if (normalized === "send-message") {
    return "这类动作会主动联系别人，通常值得你立刻确认。";
  }

  if (normalized === "delete-files") {
    return "这类动作会直接影响本地文件，最好在它继续之前先确认。";
  }

  if (normalized === "modify-files") {
    return "这类动作会改变本地文件内容，最好先确认是不是你想要的结果。";
  }

  if (normalized === "purchase-or-payment") {
    return "这类动作涉及付款或下单，通常应该始终由人来拍板。";
  }

  if (normalized === "bank-access") {
    return "这类动作触及银行或支付账户，风险很高，值得马上留意。";
  }

  if (normalized === "sensitive-secret-access") {
    return "这类动作可能接触敏感 secret，最好尽快确认是不是必要。";
  }

  if (normalized === "sensitive-data-access") {
    return "这类动作可能接触敏感数据，最好尽快确认是不是必要。";
  }

  if (severity === "critical") {
    return "这一步的风险很高，值得你马上看一眼。";
  }

  if (severity === "high-risk") {
    return "这一步已经够敏感了，最好尽快确认一下。";
  }

  return "这一步值得你留意一下，确认它是不是你真的想让 agent 去做。";
}

export function summarizeActionLabels(actions: string[], maxItems = 3): string {
  const labels = [...new Set(actions.map((action) => actionLabel(action)))];

  if (labels.length === 0) {
    return "暂无已接入的高风险动作";
  }

  if (labels.length <= maxItems) {
    return labels.join("、");
  }

  return `${labels.slice(0, maxItems).join("、")} 等 ${labels.length} 类高风险动作`;
}
