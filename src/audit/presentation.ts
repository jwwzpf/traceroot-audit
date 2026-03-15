import type { AuditEvent, AuditSeverity } from "./types";

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

  if (/(publish|post|tweet|social|tiktok|youtube|linkedin|reddit)/.test(normalized)) {
    return "公开发帖";
  }

  if (/(message|whatsapp|telegram|slack|discord|wechat)/.test(normalized)) {
    return "对外发消息";
  }

  if (/(delete|remove|rm|unlink|wipe|purge)/.test(normalized)) {
    return "删除本地文件";
  }

  if (/(write|modify|edit|update|rename|move|copy)/.test(normalized) && /(file|files|fs|disk|path|workspace)/.test(normalized)) {
    return "修改本地文件";
  }

  if (/(payment|purchase|checkout|order|stripe|paypal|wallet)/.test(normalized)) {
    return "付款或下单";
  }

  if (/(bank|finance|broker|trade|portfolio|account-balance)/.test(normalized)) {
    return "访问银行或交易数据";
  }

  if (/(secret|token|credential|password|key)/.test(normalized)) {
    return "读取敏感 secret";
  }

  if (/(sensitive|private|customer-data|pii|record|records)/.test(normalized)) {
    return "读取敏感数据";
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

export function actionTriggerContext(event: AuditEvent): string | null {
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
    return `来自 ${channel}（${senderValue}）`;
  }

  if (channel) {
    return `来自 ${channel}`;
  }

  if (senderValue) {
    return `由 ${senderValue} 触发`;
  }

  return null;
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
