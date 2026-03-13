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

function baseNotificationChoices(): CliChoice[] {
  return [
    {
      value: "local-only",
      label: "🧾 先只保留本地审计",
      hint: "高风险动作会继续记在本地时间线里，但不额外打扰你"
    },
    {
      value: "other-channel",
      label: "🔔 发到其他已接好的聊天入口",
      hint: "比如 Signal、Mattermost、Google Chat、iMessage、Teams"
    },
    {
      value: "webhook",
      label: "🪝 发到自己的提醒入口",
      hint: "如果你已经有 webhook 或自动化接收端"
    }
  ];
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
  options: { target?: string; likelyChannels?: LikelyNotifyChannel[] } = {}
): Promise<NotificationChoice> {
  const likelyChannels =
    options.likelyChannels ??
    (options.target ? await detectLikelyNotifyChannels(options.target) : []);
  const likelyChoices: CliChoice[] = likelyChannels.map((item) => ({
    value: item.channel,
    label: `${item.channel === "whatsapp" ? "📱" : item.channel === "telegram" ? "💬" : item.channel === "slack" ? "🧵" : item.channel === "discord" ? "🎮" : "🔔"} 发到已识别的 ${displayNotifyChannel(item.channel)}${item.target ? `（${item.target}）` : ""}`,
    hint: `TraceRoot 在 ${item.evidence.join("、")} 里看到了这个聊天入口`
  }));
  const staticChoices = baseNotificationChoices().filter(
    (choice) =>
      !likelyChannels.some((item) => item.channel === choice.value) &&
      !["telegram", "whatsapp", "slack", "discord"].includes(choice.value)
  );
  const quickChoices = [
    ...likelyChoices,
    ...(["telegram", "whatsapp", "slack", "discord"] as const)
      .filter((channel) => !likelyChannels.some((item) => item.channel === channel))
      .map((channel) => ({
        value: channel,
        label: `${channel === "whatsapp" ? "📱" : channel === "telegram" ? "💬" : channel === "slack" ? "🧵" : "🎮"} 发到 ${displayNotifyChannel(channel)}`,
        hint: "适合你已经在 OpenClaw 里接好这个聊天入口的情况"
      })),
    ...staticChoices
  ];

  if (likelyChannels.length > 0) {
    runtime.io.stdout(
      `✨ TraceRoot 看起来已经在这个运行态里识别到了这些聊天入口：${likelyChannels
        .map((item) =>
          item.target
            ? `${displayNotifyChannel(item.channel)}（${item.target}）`
            : displayNotifyChannel(item.channel)
        )
        .join("、")}。\n`
    );
  } else {
    runtime.io.stdout(
      "💡 TraceRoot 暂时还没认出你已经接好的聊天入口，所以这次会先只保留本地审计时间线。\n"
    );
    return { mode: "local-only" };
  }

  if (likelyChannels.length === 1 && likelyChannels[0]?.target) {
    const detected = likelyChannels[0];
    runtime.io.stdout(
      `💡 TraceRoot 这次会直接把高风险提醒顺手发到 ${displayNotifyChannel(
        detected.channel
      )}（${detected.target}）。如果你之后想改提醒方式，再重新运行 doctor 就可以。\n`
    );

    return {
      mode: "channel",
      channel: detected.channel,
      target: detected.target,
      account: detected.account
    };
  }

  const defaultNotificationChoice =
    likelyChannels[0]?.channel ?? "local-only";

  runtime.io.stdout(
    "💡 如果你想让高风险动作一出现就顺手提醒你，直接回车就可以先用 TraceRoot 推荐的那个入口。\n"
  );

  const choice = await runtime.prompter.chooseOne(
    "🔔 TraceRoot 盯到高风险动作时，要不要顺手提醒你？",
    quickChoices,
    { defaultValue: defaultNotificationChoice }
  );

  if (choice === "local-only") {
    return { mode: "local-only" };
  }

  if (choice === "webhook") {
    return { mode: "webhook" };
  }

  let channel = choice;
  const detectedChannel = likelyChannels.find((item) => item.channel === channel);
  if (choice === "other-channel") {
    channel = await runtime.prompter.chooseOne(
      "💡 你想用哪个已接好的聊天入口？",
      SUPPORTED_OPENCLAW_NOTIFY_CHANNELS.filter(
        (value) => !["telegram", "whatsapp", "slack", "discord"].includes(value)
      ).map((value) => ({
        value,
        label: value,
        hint: "前提是 OpenClaw 已经接好了这个入口"
      }))
    );
  }

  const target =
    detectedChannel?.target ??
    (await runtime.prompter.input(
      `📨 TraceRoot 应该把提醒发到哪里？（${displayNotifyChannel(channel)}）`,
      { allowEmpty: false }
    ));

  return {
    mode: "channel",
    channel,
    target,
    account: detectedChannel?.account
  };
}
