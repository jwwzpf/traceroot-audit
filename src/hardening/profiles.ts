import type { TraceRootManifest } from "../manifest/schema";

export type HardeningIntentId =
  | "email-reply"
  | "social-posting"
  | "shopping-automation"
  | "pr-review"
  | "chat-support"
  | "market-monitoring";

export type SupportedCapability =
  | "shell"
  | "network"
  | "filesystem"
  | "browser"
  | "email"
  | "payments";

export type SecretGroup =
  | "email"
  | "social"
  | "payment"
  | "finance"
  | "messaging"
  | "cloud"
  | "database"
  | "ai"
  | "browser"
  | "general";

export interface HardeningIntentProfile {
  id: HardeningIntentId;
  icon: string;
  title: string;
  subtitle: string;
  expectedActions: string[];
  requiredCapabilities: SupportedCapability[];
  optionalCapabilities: SupportedCapability[];
  sideEffects: boolean;
  riskLevel: TraceRootManifest["risk_level"];
  allowedSecretGroups: SecretGroup[];
  recommendedSafeguards: string[];
}

export const hardeningIntentProfiles: HardeningIntentProfile[] = [
  {
    id: "email-reply",
    icon: "📧",
    title: "邮件整理与回复",
    subtitle: "读取邮件、起草回复、在确认后发送",
    expectedActions: ["send-email"],
    requiredCapabilities: ["network", "email"],
    optionalCapabilities: ["browser"],
    sideEffects: true,
    riskLevel: "high",
    allowedSecretGroups: ["email", "ai", "general"],
    recommendedSafeguards: [
      "require confirmation before sending outbound email",
      "keep shell disabled for the active runtime",
      "separate unrelated app secrets from the email workflow env"
    ]
  },
  {
    id: "social-posting",
    icon: "🧵",
    title: "社交媒体发帖 / 运营",
    subtitle: "发 X/Twitter 更新，管理社媒发布流程",
    expectedActions: ["public-post"],
    requiredCapabilities: ["network", "browser"],
    optionalCapabilities: ["filesystem"],
    sideEffects: true,
    riskLevel: "high",
    allowedSecretGroups: ["social", "ai", "browser", "general"],
    recommendedSafeguards: [
      "require confirmation before publishing public posts",
      "bind the runtime to localhost only",
      "keep payments and shell capabilities disabled"
    ]
  },
  {
    id: "shopping-automation",
    icon: "🛒",
    title: "购物 / 下单自动化",
    subtitle: "购物车、配送时段、确认订单",
    expectedActions: ["purchase-or-payment"],
    requiredCapabilities: ["network", "browser"],
    optionalCapabilities: ["payments", "email"],
    sideEffects: true,
    riskLevel: "critical",
    allowedSecretGroups: ["payment", "email", "browser", "general"],
    recommendedSafeguards: [
      "require confirmation before any purchase or checkout step",
      "keep shell and broad filesystem writes disabled",
      "store payment credentials outside the default runtime env"
    ]
  },
  {
    id: "pr-review",
    icon: "💻",
    title: "PR 审查 / 代码反馈",
    subtitle: "代码变更审查、反馈回传到聊天渠道",
    expectedActions: ["send-message", "modify-files"],
    requiredCapabilities: ["network", "filesystem"],
    optionalCapabilities: ["browser"],
    sideEffects: false,
    riskLevel: "medium",
    allowedSecretGroups: ["ai", "messaging", "general"],
    recommendedSafeguards: [
      "keep payments and email sending disabled",
      "limit filesystem writes to the workspace or temp output only",
      "review whether shell is truly required for this workflow"
    ]
  },
  {
    id: "chat-support",
    icon: "💬",
    title: "客服 / 聊天支持 / 消息代发",
    subtitle: "在聊天渠道自动回复或转发消息",
    expectedActions: ["send-message", "send-email"],
    requiredCapabilities: ["network"],
    optionalCapabilities: ["browser", "email"],
    sideEffects: true,
    riskLevel: "high",
    allowedSecretGroups: ["messaging", "email", "ai", "general"],
    recommendedSafeguards: [
      "require confirmation for outbound messages unless you explicitly allow autonomy",
      "bind runtime access to localhost or a trusted private interface",
      "keep shell disabled unless message handling truly needs it"
    ]
  },
  {
    id: "market-monitoring",
    icon: "📈",
    title: "市场监控 / 图表分析",
    subtitle: "查看图表、抓截图、做技术分析",
    expectedActions: ["bank-access", "finance-access", "sensitive-data-access"],
    requiredCapabilities: ["network"],
    optionalCapabilities: ["browser", "filesystem"],
    sideEffects: false,
    riskLevel: "medium",
    allowedSecretGroups: ["finance", "ai", "browser", "general"],
    recommendedSafeguards: [
      "treat trading or order execution as a separate higher-risk workflow",
      "keep payments and email sending disabled",
      "prefer read-only data access and no public runtime exposure"
    ]
  }
];

export function getHardeningProfileById(id: HardeningIntentId): HardeningIntentProfile {
  const profile = hardeningIntentProfiles.find((entry) => entry.id === id);

  if (!profile) {
    throw new Error(`Unknown hardening intent: ${id}`);
  }

  return profile;
}

function normalizeActionForWorkflowScope(action?: string): string | null {
  const normalized = action?.trim().toLowerCase();

  if (!normalized) {
    return null;
  }

  if (
    [
      "send-email",
      "public-post",
      "send-message",
      "delete-files",
      "modify-files",
      "purchase-or-payment",
      "bank-access",
      "finance-access",
      "sensitive-secret-access",
      "sensitive-data-access"
    ].includes(normalized)
  ) {
    return normalized;
  }

  if (/(send|draft).*(email|mail)|(email|mail).*(send|draft)/.test(normalized)) {
    return "send-email";
  }

  if (/(publish|publishing|post|posting|tweet|social|tiktok|youtube|linkedin|reddit)/.test(normalized)) {
    return "public-post";
  }

  if (/(message|whatsapp|telegram|slack|discord|wechat)/.test(normalized)) {
    return "send-message";
  }

  if (/(delete|deleting|remove|removing|rm|unlink|wipe|wiping|purge)/.test(normalized)) {
    return "delete-files";
  }

  if (/(write|writing|modify|modifying|edit|editing|update|updating|rename|renaming|move|moving|copy|copying)/.test(normalized)) {
    return "modify-files";
  }

  if (/(payment|paying|purchase|purchasing|checkout|checking out|order|ordering|stripe|paypal|wallet)/.test(normalized)) {
    return "purchase-or-payment";
  }

  if (/(bank|banking|finance|financial|broker|trade|trading|portfolio|account-balance)/.test(normalized)) {
    return "bank-access";
  }

  if (/(sensitive|private|customer-data|customer data|pii|record|records|dataset|datasets)/.test(normalized)) {
    return "sensitive-data-access";
  }

  if (/(secret|secrets|token|tokens|credential|credentials|password|passwords|key|keys)/.test(normalized)) {
    return "sensitive-secret-access";
  }

  return normalized;
}

export function workflowScopeNoteForAction(
  action: string | undefined,
  intentIds: HardeningIntentId[]
): string | null {
  if (!action || intentIds.length === 0) {
    return null;
  }

  const normalizedAction = normalizeActionForWorkflowScope(action);
  if (!normalizedAction || normalizedAction.startsWith("openclaw-command-")) {
    return null;
  }

  const selectedProfiles = intentIds.map((intentId) => getHardeningProfileById(intentId));
  const matchingProfiles = selectedProfiles.filter((profile) =>
    profile.expectedActions.includes(normalizedAction)
  );

  if (matchingProfiles.length > 0) {
    return null;
  }

  if (selectedProfiles.length === 1) {
    return `这一步看起来超出了你批准过的工作流「${selectedProfiles[0]!.title}」。`;
  }

  return `这一步看起来不在你批准过的这些工作流里：${selectedProfiles
    .map((profile) => profile.title)
    .join("、")}。`;
}

export function workflowScopeUserWarningForAction(
  action: string | undefined,
  intentIds: HardeningIntentId[]
): string | null {
  if (!action || intentIds.length === 0) {
    return null;
  }

  const normalizedAction = normalizeActionForWorkflowScope(action);
  if (!normalizedAction || normalizedAction.startsWith("openclaw-command-")) {
    return null;
  }

  const selectedProfiles = intentIds.map((intentId) => getHardeningProfileById(intentId));
  const matchingProfiles = selectedProfiles.filter((profile) =>
    profile.expectedActions.includes(normalizedAction)
  );

  if (matchingProfiles.length > 0) {
    return null;
  }

  if (selectedProfiles.length === 1) {
    return `这一步看起来不是你刚才让 agent 做的事，已经超出了「${selectedProfiles[0]!.title}」这类工作流。`;
  }

  return `这一步看起来不是你刚才让 agent 做的事，也不在你批准过的这些工作流里：${selectedProfiles
    .map((profile) => profile.title)
    .join("、")}。`;
}
