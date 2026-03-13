import { discoverHost } from "../core/discovery";
import { surfaceLabel } from "../core/surfaces";
import type { CliChoice, CliRuntime } from "../cli/index";
import { SUPPORTED_OPENCLAW_NOTIFY_CHANNELS } from "../audit/notifier";
import type {
  ExposureMode,
  FilesystemScope,
  HardeningSelections,
  OutboundApprovalMode
} from "./analysis";
import { hardeningIntentProfiles, type HardeningIntentId } from "./profiles";

function intentChoices(): CliChoice[] {
  return hardeningIntentProfiles.map((profile) => ({
    value: profile.id,
    label: `${profile.icon} ${profile.title}`,
    hint: profile.subtitle
  }));
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

function notificationChoices(): CliChoice[] {
  return [
    {
      value: "local-only",
      label: "🧾 先只保留本地审计",
      hint: "高风险动作会继续记在本地时间线里，但不额外打扰你"
    },
    {
      value: "telegram",
      label: "💬 发到 Telegram",
      hint: "适合你已经在 OpenClaw 里接好 Telegram 的情况"
    },
    {
      value: "whatsapp",
      label: "📱 发到 WhatsApp",
      hint: "适合你已经在 OpenClaw 里接好 WhatsApp 的情况"
    },
    {
      value: "slack",
      label: "🧵 发到 Slack",
      hint: "适合团队一起盯高风险动作"
    },
    {
      value: "discord",
      label: "🎮 发到 Discord",
      hint: "适合社区或机器人频道"
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
  runtime: CliRuntime
): Promise<HardeningSelections> {
  const intentIds = (await runtime.prompter.chooseMany(
    "✨ What do you want this AI to do? Choose one or more workflows:",
    intentChoices()
  )) as HardeningIntentId[];
  const outboundApproval = (await runtime.prompter.chooseOne(
    "🛑 How should outbound side-effecting actions behave?",
    approvalChoices()
  )) as OutboundApprovalMode;
  const filesystemScope = (await runtime.prompter.chooseOne(
    "📁 How much local file write access should this workflow have?",
    fileScopeChoices()
  )) as FilesystemScope;
  const exposureMode = (await runtime.prompter.chooseOne(
    "🌐 Should this runtime be reachable from other devices?",
    exposureChoices()
  )) as ExposureMode;

  return {
    intentIds,
    outboundApproval,
    filesystemScope,
    exposureMode
  };
}

export async function promptNotificationSelection(
  runtime: CliRuntime
): Promise<NotificationChoice> {
  const choice = await runtime.prompter.chooseOne(
    "🔔 TraceRoot 盯到高风险动作时，要不要顺手提醒你？",
    notificationChoices()
  );

  if (choice === "local-only") {
    return { mode: "local-only" };
  }

  if (choice === "webhook") {
    return { mode: "webhook" };
  }

  let channel = choice;
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

  const target = await runtime.prompter.input(
    `📨 TraceRoot 应该把提醒发到哪里？（${channel}）`,
    { allowEmpty: false }
  );

  const wantsAccount = await runtime.prompter.confirm(
    "👤 这个聊天入口需要指定 OpenClaw 账户名吗？",
    false
  );
  const account = wantsAccount
    ? await runtime.prompter.input("填写账户名", { allowEmpty: false })
    : undefined;

  return {
    mode: "channel",
    channel,
    target,
    account
  };
}
