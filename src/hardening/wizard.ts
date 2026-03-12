import { discoverHost } from "../core/discovery";
import { surfaceLabel } from "../core/surfaces";
import type { CliChoice, CliRuntime } from "../cli/index";
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
