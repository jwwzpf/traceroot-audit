import {
  discoverHost,
  hostCandidateAttentionForHuman
} from "../core/discovery";
import { surfaceLabel } from "../core/surfaces";
import type { CliChoice, CliRuntime } from "../cli/index";
import { SUPPORTED_OPENCLAW_NOTIFY_CHANNELS } from "../audit/notifier";
import {
  detectLikelyNotifyChannels,
  displayNotifyChannel,
  type LikelyNotifyChannel
} from "./notify-discovery";
import { getCliLanguage } from "../cli/locale";
import { discoverFiles, resolveTarget } from "../utils/files";
import type {
  ExposureMode,
  FilesystemScope,
  HardeningSelections,
  OutboundApprovalMode
} from "./analysis";
import {
  getHardeningProfileById,
  hardeningIntentProfiles,
  type HardeningIntentId
} from "./profiles";

function intentChoices(): CliChoice[] {
  return hardeningIntentProfiles.map((profile) => ({
    value: profile.id,
    label: `${profile.icon} ${profile.title}`,
    hint: profile.subtitle
  }));
}

const intentSignalMatchers: Record<HardeningIntentId, RegExp[]> = {
  "email-reply": [
    /\bemail\b/i,
    /\bgmail\b/i,
    /\bsmtp\b/i,
    /\binbox\b/i,
    /\bresend\b/i,
    /\bsendgrid\b/i,
    /\bmail(?:er|gun)?\b/i
  ],
  "social-posting": [
    /\btwitter\b/i,
    /\bx\.com\b/i,
    /\btweet\b/i,
    /\bsocial\b/i,
    /\bpost(?:ing)?\b/i,
    /\bpublish\b/i,
    /\btiktok\b/i,
    /\binstagram\b/i,
    /\byoutube\b/i
  ],
  "shopping-automation": [
    /\bshop(?:ping)?\b/i,
    /\border\b/i,
    /\bcart\b/i,
    /\bcheckout\b/i,
    /\bpurchase\b/i,
    /\bdelivery\b/i,
    /\bstripe\b/i,
    /\bpaypal\b/i
  ],
  "pr-review": [
    /\bpr\b/i,
    /\bpull[- ]request\b/i,
    /\breview\b/i,
    /\bgithub\b/i,
    /\bgitlab\b/i,
    /\bdiff\b/i,
    /\bcommit\b/i
  ],
  "chat-support": [
    /\bchat\b/i,
    /\bsupport\b/i,
    /\bmessage\b/i,
    /\bcustomer\b/i,
    /\bticket\b/i,
    /\bhelpdesk\b/i,
    /\btwilio\b/i
  ],
  "market-monitoring": [
    /\bmarket\b/i,
    /\bchart\b/i,
    /\btradingview\b/i,
    /\bstock\b/i,
    /\bbroker\b/i,
    /\bprice\b/i,
    /\bbinance\b/i,
    /\bcoinbase\b/i,
    /\bportfolio\b/i
  ]
};

async function suggestIntentIdsForTarget(targetInput: string): Promise<HardeningIntentId[]> {
  const resolvedTarget = await resolveTarget(targetInput);
  const files = await discoverFiles(resolvedTarget);
  const scores = new Map<HardeningIntentId, number>();

  for (const profile of hardeningIntentProfiles) {
    scores.set(profile.id, 0);
  }

  for (const file of files) {
    const relativePath = file.relativePath.toLowerCase();
    const contentSample = file.content.slice(0, 4000);
    const combinedText = `${relativePath}\n${contentSample}`;

    for (const [intentId, patterns] of Object.entries(intentSignalMatchers) as Array<
      [HardeningIntentId, RegExp[]]
    >) {
      const matches = patterns.filter((pattern) => pattern.test(combinedText)).length;
      if (matches > 0) {
        scores.set(intentId, (scores.get(intentId) ?? 0) + matches);
      }
    }
  }

  return [...scores.entries()]
    .filter(([, score]) => score > 0)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 2)
    .map(([intentId]) => intentId);
}

function approvalChoices(): CliChoice[] {
  return [
    {
      value: "always-confirm",
      label: "🛑 每次外发动作都确认",
      hint: "最稳妥，适合邮件、下单、发帖等场景"
    },
    {
      value: "confirm-high-risk",
      label: "⚠️ 仅高风险动作确认",
      hint: "低风险自动执行，高风险动作要求人工确认"
    },
    {
      value: "allow-autonomous",
      label: "🤖 允许自主外发",
      hint: "风险最高，只适合你明确接受自动执行的场景"
    }
  ];
}

function fileScopeChoices(): CliChoice[] {
  return [
    {
      value: "no-write",
      label: "🚫 不允许写本地文件",
      hint: "只读更安全"
    },
    {
      value: "workspace-only",
      label: "📁 仅允许写工作目录",
      hint: "推荐默认选项"
    },
    {
      value: "broad-write",
      label: "🧨 允许更广泛写文件",
      hint: "只有在确实需要时再选"
    }
  ];
}

function exposureChoices(): CliChoice[] {
  return [
    {
      value: "localhost-only",
      label: "🏠 仅本机访问",
      hint: "推荐默认选项，避免局域网或公网可达"
    },
    {
      value: "lan-access",
      label: "🌐 允许局域网访问",
      hint: "只在你明确需要跨设备访问时使用"
    }
  ];
}

type NotificationChoice =
  | { mode: "local-only" }
  | { mode: "webhook" }
  | { mode: "channel"; channel: string; target: string; account?: string };

function notifyChannelIcon(channel: string): string {
  switch (channel) {
    case "whatsapp":
      return "📱";
    case "telegram":
      return "💬";
    case "discord":
      return "🎮";
    case "slack":
      return "🧵";
    case "signal":
      return "🛰️";
    case "googlechat":
      return "💠";
    case "mattermost":
      return "💭";
    case "imessage":
      return "💙";
    case "msteams":
      return "🪟";
    default:
      return "🔔";
  }
}

function usesChineseCli(): boolean {
  return getCliLanguage() === "zh";
}

function baseNotificationChoices(): CliChoice[] {
  return [
    {
      value: "local-only",
      label: usesChineseCli() ? "🧾 先只保留本地审计" : "🧾 Local audit only"
    },
    {
      value: "webhook",
      label: usesChineseCli() ? "🪝 Webhook / 自定义入口" : "🪝 Webhook / custom endpoint"
    }
  ];
}

function notificationQuestion(): string {
  return usesChineseCli()
    ? "🔔 你想把高风险提醒发到哪里？"
    : "🔔 Where do you want high-risk reminders to go?";
}

function notifyConfiguredMessage(channel: string, target: string): string {
  if (usesChineseCli()) {
    return `✨ TraceRoot 已经能把提醒发到 ${displayNotifyChannel(channel)}（${target}）。这次会直接用它。\n`;
  }

  return `✨ TraceRoot can already send reminders to ${displayNotifyChannel(channel)} (${target}). TraceRoot will use that route this time.\n`;
}

function localAuditFallbackMessage(channel: string): string {
  if (usesChineseCli()) {
    return `🧾 没关系，这次先只保留本地审计时间线。等你把 ${displayNotifyChannel(channel)} 接好以后，再回来打开提醒就可以。\n`;
  }

  return `🧾 No problem. This run will keep a local audit timeline only for now. Once ${displayNotifyChannel(channel)} is connected, you can come back and turn reminders on.\n`;
}

type ChannelSetupGuide = {
  title: string;
  steps: string[];
  prompt: string;
};

function targetRequirementHint(channel: string): ChannelSetupGuide {
  switch (channel) {
    case "whatsapp":
      return {
        title: usesChineseCli()
          ? "📱 连接 WhatsApp，只要跟着这几步走："
          : "📱 Connect WhatsApp in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 在 OpenClaw 里运行 `openclaw channels login --channel whatsapp`。",
              "2. OpenClaw 会显示一个二维码。",
              "3. 用手机上的 WhatsApp 扫这个二维码。",
              "4. 重启 `openclaw gateway`。",
              "5. 如果你已经知道提醒要发到哪个号码或聊天目标，现在就贴进来，例如：+4917612345678。",
              "6. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Run `openclaw channels login --channel whatsapp` inside OpenClaw.",
              "2. OpenClaw will show you a QR code.",
              "3. Scan that QR code with WhatsApp on your phone.",
              "4. Restart `openclaw gateway`.",
              "5. If you already know the phone number or chat target, paste it below, for example: +4917612345678.",
              "6. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 WhatsApp 号码或聊天目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the WhatsApp number or chat target here (or press Enter to skip for now)"
      };
    case "telegram":
      return {
        title: usesChineseCli()
          ? "💬 连接 Telegram，只要跟着这几步走："
          : "💬 Connect Telegram in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 在 Telegram 里打开 @BotFather，创建一个机器人。",
              "2. 把机器人 token 配进 OpenClaw（例如 `channels.telegram.botToken`）。",
              "3. 重启 `openclaw gateway`。",
              "4. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：@ops-room 或 chat id。",
              "5. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Open @BotFather in Telegram and create a bot.",
              "2. Put the bot token into OpenClaw, for example in `channels.telegram.botToken`.",
              "3. Restart `openclaw gateway`.",
              "4. If you already know the chat target, paste it below, for example: @ops-room or a chat id.",
              "5. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 Telegram 聊天目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the Telegram chat target here (or press Enter to skip for now)"
      };
    case "discord":
      return {
        title: usesChineseCli()
          ? "🎮 连接 Discord，只要跟着这几步走："
          : "🎮 Connect Discord in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 先把 Discord 机器人接进 OpenClaw。",
              "2. 重启 `openclaw gateway`。",
              "3. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：channel:123456789 或 user:123456789。",
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Connect your Discord bot inside OpenClaw.",
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below, for example: channel:123456789 or user:123456789.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 Discord 频道或用户目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the Discord channel or user target here (or press Enter to skip for now)"
      };
    case "slack":
      return {
        title: usesChineseCli()
          ? "🧵 连接 Slack，只要跟着这几步走："
          : "🧵 Connect Slack in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 先把 Slack 接进 OpenClaw。",
              "2. 重启 `openclaw gateway`。",
              "3. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：channel:C123456 或 user:U123456。",
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Connect Slack inside OpenClaw.",
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below, for example: channel:C123456 or user:U123456.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 Slack 频道或用户目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the Slack channel or user target here (or press Enter to skip for now)"
      };
    case "signal":
      return {
        title: usesChineseCli()
          ? "🛰️ 连接 Signal，只要跟着这几步走："
          : "🛰️ Connect Signal in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 先把 Signal 接进 OpenClaw。",
              "2. 重启 `openclaw gateway`。",
              "3. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：+4917612345678 或 group:<id>。",
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Connect Signal inside OpenClaw.",
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below, for example: +4917612345678 or group:<id>.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 Signal 号码或群组目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the Signal number or group target here (or press Enter to skip for now)"
      };
    case "googlechat":
      return {
        title: usesChineseCli()
          ? "💠 连接 Google Chat，只要跟着这几步走："
          : "💠 Connect Google Chat in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 先把 Google Chat 接进 OpenClaw。",
              "2. 重启 `openclaw gateway`。",
              "3. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：spaces/<spaceId>。",
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Connect Google Chat inside OpenClaw.",
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below, for example: spaces/<spaceId>.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 Google Chat 目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the Google Chat target here (or press Enter to skip for now)"
      };
    case "mattermost":
      return {
        title: usesChineseCli()
          ? "💭 连接 Mattermost，只要跟着这几步走："
          : "💭 Connect Mattermost in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 先把 Mattermost 接进 OpenClaw。",
              "2. 重启 `openclaw gateway`。",
              "3. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：@ops-room 或 channel:<id>。",
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Connect Mattermost inside OpenClaw.",
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below, for example: @ops-room or channel:<id>.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 Mattermost 频道或用户目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the Mattermost channel or user target here (or press Enter to skip for now)"
      };
    case "imessage":
      return {
        title: usesChineseCli()
          ? "💙 连接 iMessage，只要跟着这几步走："
          : "💙 Connect iMessage in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 先把 iMessage 接进 OpenClaw。",
              "2. 重启 `openclaw gateway`。",
              "3. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：chat_id:<id> 或联系人号码/邮箱。",
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Connect iMessage inside OpenClaw.",
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below, for example: chat_id:<id> or a contact phone/email.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 iMessage 聊天目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the iMessage chat target here (or press Enter to skip for now)"
      };
    case "msteams":
      return {
        title: usesChineseCli()
          ? "🪟 连接 Microsoft Teams，只要跟着这几步走："
          : "🪟 Connect Microsoft Teams in a few simple steps:",
        steps: usesChineseCli()
          ? [
              "1. 先把 Microsoft Teams 接进 OpenClaw。",
              "2. 重启 `openclaw gateway`。",
              "3. 如果你已经知道提醒要发到哪里，现在就贴进来，例如：conversation:<id>。",
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              "1. Connect Microsoft Teams inside OpenClaw.",
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below, for example: conversation:<id>.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? "📨 把 Microsoft Teams 会话目标贴在这里（可直接回车，先跳过）"
          : "📨 Paste the Microsoft Teams conversation target here (or press Enter to skip for now)"
      };
    default:
      return {
        title: usesChineseCli()
          ? `🔔 连接 ${displayNotifyChannel(channel)}，只要跟着这几步走：`
          : `🔔 Connect ${displayNotifyChannel(channel)} in a few simple steps:`,
        steps: usesChineseCli()
          ? [
              `1. 先把 ${displayNotifyChannel(channel)} 接进 OpenClaw。`,
              "2. 重启 `openclaw gateway`。",
              `3. 如果你已经知道提醒要发到哪里，现在就贴进来。`,
              "4. 如果你现在还不确定，直接回车就行，TraceRoot 会先只保留本地审计时间线。"
            ]
          : [
              `1. Connect ${displayNotifyChannel(channel)} inside OpenClaw.`,
              "2. Restart `openclaw gateway`.",
              "3. If you already know the target, paste it below.",
              "4. If you are not sure yet, just press Enter and TraceRoot will keep local audit only for now."
            ],
        prompt: usesChineseCli()
          ? `📨 把 ${displayNotifyChannel(channel)} 的聊天目标贴在这里（可直接回车，先跳过）`
          : `📨 Paste the ${displayNotifyChannel(channel)} chat target here (or press Enter to skip for now)`
      };
  }
}

export async function resolveWizardTarget(
  runtime: CliRuntime,
  options: {
    target?: string;
    host?: boolean;
    includeCwd?: boolean;
    emptyStateTitle: string;
    emptyStateHint: string;
    chooseTargetQuestion: string;
  }
): Promise<string | null> {
  const shouldUseHostDiscovery = options.host || !options.target;

  if (!shouldUseHostDiscovery) {
    return options.target ?? ".";
  }

  const hostDiscovery = await discoverHost({
    includeCwd: options.includeCwd ?? false
  });

  if (hostDiscovery.candidates.length === 0) {
    runtime.io.stdout(
      [
        options.emptyStateTitle,
        "".padEnd(options.emptyStateTitle.length, "="),
        "",
        options.emptyStateHint
      ].join("\n") + "\n"
    );
    return null;
  }

  const bestFirstCandidates = hostDiscovery.candidates.filter(
    (candidate) => candidate.tier === "best-first"
  );

  if (hostDiscovery.candidates.length === 1) {
    const candidate = hostDiscovery.candidates[0]!;
    runtime.io.stdout(
      `🎯 TraceRoot 已经帮你锁定了最值得先看的位置：${candidate.displayPath}。\n`
    );
    runtime.io.stdout(
      `🧭 原因：${hostCandidateAttentionForHuman(candidate)} 先从这里开始最省心。\n\n`
    );
    return candidate.absolutePath;
  }

  if (bestFirstCandidates.length === 1) {
    const candidate = bestFirstCandidates[0]!;
    runtime.io.stdout(
      `🎯 TraceRoot 看起来已经帮你锁定了当前最像 agent/runtime 的入口：${candidate.displayPath}。\n`
    );
    runtime.io.stdout(
      `🧭 原因：${hostCandidateAttentionForHuman(candidate)} 先从这里开始最合适。\n\n`
    );
    return candidate.absolutePath;
  }

  return runtime.prompter.chooseOne(
    options.chooseTargetQuestion,
    hostDiscovery.candidates.map((candidate) => ({
      value: candidate.absolutePath,
      label: `${candidate.displayPath} (${surfaceLabel(candidate.surface.kind)})`,
      hint: candidate.surface.reasons[0]
    }))
  );
}

export async function promptHardeningSelections(
  runtime: CliRuntime,
  targetInput?: string
): Promise<HardeningSelections> {
  const suggestedIntentIds = targetInput
    ? await suggestIntentIdsForTarget(targetInput)
    : [];

  if (suggestedIntentIds.length > 0) {
    runtime.io.stdout(
      `✨ TraceRoot 看起来你这次更像想让 AI 做这些事：${suggestedIntentIds
        .map((intentId) => {
          const profile = getHardeningProfileById(intentId);
          return `${profile.icon} ${profile.title}`;
        })
        .join("、")}。\n`
    );
    runtime.io.stdout(
      "💡 如果这组推荐正好符合你现在的目标，直接回车就可以先按这套继续。\n\n"
    );
  }

  const intentIds = (await runtime.prompter.chooseMany(
    "✨ 这次你想让这个 AI 主要帮你做什么？可以选一个或多个工作流：",
    intentChoices(),
    { defaultValues: suggestedIntentIds }
  )) as HardeningIntentId[];
  const outboundApproval = (await runtime.prompter.chooseOne(
    "🛑 外发或副作用动作，TraceRoot 默认该怎么帮你守住？",
    approvalChoices(),
    { defaultValue: "always-confirm" }
  )) as OutboundApprovalMode;
  const filesystemScope = (await runtime.prompter.chooseOne(
    "📁 这套工作流最多该碰到多大的本地写文件范围？",
    fileScopeChoices(),
    { defaultValue: "workspace-only" }
  )) as FilesystemScope;
  const exposureMode = (await runtime.prompter.chooseOne(
    "🌐 这个运行态要不要允许其他设备连进来？",
    exposureChoices(),
    { defaultValue: "localhost-only" }
  )) as ExposureMode;

  return {
    intentIds,
    outboundApproval,
    filesystemScope,
    exposureMode
  };
}

export async function promptNotificationSelection(
  runtime: CliRuntime,
  options: { target?: string; likelyChannels?: LikelyNotifyChannel[]; quiet?: boolean } = {}
): Promise<NotificationChoice> {
  const likelyChannels =
    options.likelyChannels ??
    (options.target ? await detectLikelyNotifyChannels(options.target) : []);
  const simpleChannelChoices = SUPPORTED_OPENCLAW_NOTIFY_CHANNELS.map((channel) => ({
    value: channel,
    label: `${notifyChannelIcon(channel)} ${displayNotifyChannel(channel)}`
  }));
  const quickChoices = [...simpleChannelChoices, ...baseNotificationChoices()];

  const defaultNotificationChoice =
    likelyChannels.find((item) => item.target)?.channel ?? "local-only";

  const choice = await runtime.prompter.chooseOne(
    notificationQuestion(),
    quickChoices,
    { defaultValue: defaultNotificationChoice }
  );

  if (choice === "local-only") {
    return { mode: "local-only" };
  }

  if (choice === "webhook") {
    return { mode: "webhook" };
  }

  const channel = choice;
  const detectedChannel = likelyChannels.find(
    (item) => item.channel === channel && item.target
  );

  if (detectedChannel?.target) {
    if (!options.quiet) {
      runtime.io.stdout(notifyConfiguredMessage(channel, detectedChannel.target));
    }

    return {
      mode: "channel",
      channel: detectedChannel.channel,
      target: detectedChannel.target,
      account: detectedChannel.account
    };
  }

  const guide = targetRequirementHint(channel);
  if (!options.quiet) {
    runtime.io.stdout(`${guide.title}\n`);
    for (const step of guide.steps) {
      runtime.io.stdout(`${step}\n`);
    }
    runtime.io.stdout("\n");
  }

  const target = await runtime.prompter.input(guide.prompt, {
    allowEmpty: true
  });

  if (!target.trim()) {
    runtime.io.stdout(localAuditFallbackMessage(channel));
    return { mode: "local-only" };
  }

  return {
    mode: "channel",
    channel,
    target,
    account: detectedChannel?.account
  };
}
