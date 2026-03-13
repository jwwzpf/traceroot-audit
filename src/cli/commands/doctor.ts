import path from "node:path";

import { Command } from "commander";

import {
  buildCurrentHardeningState,
  buildHardeningPlan
} from "../../hardening/analysis";
import type { HardeningSelections } from "../../hardening/analysis";
import { writeApplyBundle } from "../../hardening/apply";
import { evaluateBoundaryStatus } from "../../hardening/boundary";
import {
  loadHardeningProfile,
  type SavedHardeningProfile
} from "../../hardening/profile";
import {
  loadWatchPreferences,
  saveWatchPreferences
} from "../../hardening/watch-preferences";
import {
  loadRecentDoctorTarget,
  recentTargetLabel,
  saveRecentDoctorTarget
} from "../../hardening/recent-target";
import { writeHardeningFiles } from "../../hardening/writer";
import {
  promptHardeningSelections,
  promptNotificationSelection,
  resolveWizardTarget
} from "../../hardening/wizard";
import { recommendedManifestFormat } from "../../hardening/analysis";
import { summarizeActionLabels } from "../../audit/presentation";
import { displayNotifyChannel } from "../../hardening/notify-discovery";
import { detectLikelyNotifyChannelsForTargets } from "../../hardening/notify-discovery";
import { runTargetWatch } from "../watch";
import { displayUserPath } from "../../utils/paths";
import { resolveTarget } from "../../utils/files";
import { discoverHost } from "../../core/discovery";
import { runHostWatch } from "../watch";

import type { CliRuntime } from "../index";

function renderDoctorSummary(options: {
  target: string;
  plan: Awaited<ReturnType<typeof buildHardeningPlan>>;
  selectedWorkflows: string[];
  bundle: Awaited<ReturnType<typeof writeApplyBundle>>;
  boundaryStatus: ReturnType<typeof evaluateBoundaryStatus>;
}): string {
  function displayPath(filePath: string): string {
    const relativePath = path.relative(options.plan.rootDir, filePath);
    if (!relativePath || relativePath === "") {
      return ".";
    }

    return relativePath.startsWith("..") ? filePath : `./${relativePath}`;
  }

  function formatCapabilities(capabilities: string[]): string {
    return capabilities.length > 0 ? capabilities.join(", ") : "none detected";
  }

  const currentPower = formatCapabilities(options.plan.currentCapabilities);
  const approvedPower = formatCapabilities(options.plan.recommendedCapabilities);
  const capabilitiesChanged = currentPower !== approvedPower;

  const lines = [
    "TraceRoot Audit Doctor",
    "======================",
    "",
    `🎯 当前处理位置：${displayUserPath(options.plan.rootDir)}`,
    `🧩 你刚批准的工作流：${options.selectedWorkflows.join(", ")}`,
    "🛠️ TraceRoot 正在帮你收紧边界，并准备更安全的补丁包...",
    ""
  ];

  if (capabilitiesChanged) {
    lines.push(
      "📉 权限收缩预览：",
      `- 现在：${currentPower}`,
      `- 收紧后：${approvedPower}`
    );
  } else {
    lines.push(
      "📉 这次收紧的重点：",
      `- 动作能力：${currentPower}`,
      "- 这次不需要再给 agent 更多动作能力，TraceRoot 会重点收紧它的运行方式。"
    );
  }

  lines.push(
    `- 审批方式：${options.plan.approvalPolicy}`,
    `- 文件写入范围：${options.plan.fileWritePolicy}`,
    `- 网络暴露范围：${options.plan.exposurePolicy}`,
    "",
    "✨ TraceRoot 已经先帮你准备好了这些内容：",
    `- 📜 更小权限的 manifest 建议：${displayPath(options.bundle.manifestPath)}`,
    `- 🧭 应用步骤说明：${displayPath(options.bundle.planPath)}`
  );

  if (options.bundle.envExamplePath) {
    lines.push(`- 🔐 更干净的运行时环境变量模板：${displayPath(options.bundle.envExamplePath)}`);
  }

  if (options.bundle.composeOverridePath) {
    lines.push(`- 🌐 更安全的 compose 覆盖文件：${displayPath(options.bundle.composeOverridePath)}`);
  }

  if (options.boundaryStatus.aligned) {
    lines.push(
      "",
      "✅ 好消息：你当前的配置已经和刚批准的边界对齐了。",
      "💓 如果你想继续陪跑守护它，下一步直接打开 Doctor Watch 就可以了。"
    );

    return `${lines.join("\n")}\n`;
  }

  const preparedFixes: string[] = [];
  const preparedOutcomes: string[] = [];
  const stillNeedsUser = [];

  for (const violation of options.boundaryStatus.violations) {
    if (
      violation.code === "public-exposure" &&
      options.bundle.composeOverridePath &&
      options.bundle.composeSourcePath
    ) {
      preparedFixes.push(
        `🌐 公开暴露这一步 → 更安全的 compose 覆盖文件已经准备好了（${displayPath(options.bundle.composeOverridePath)}）`
      );
      preparedOutcomes.push("🌐 尽量把 runtime 收回到本机，不再继续暴露给更大的网络范围");
      continue;
    }

    if (violation.code === "missing-confirmation") {
      preparedFixes.push(
        `📜 确认保护这一步 → hardened manifest 已经准备好了（${displayPath(options.bundle.manifestPath)}）`
      );
      preparedOutcomes.push("📜 在真正执行外发或副作用动作前，先把确认步骤卡住");
      continue;
    }

    if (violation.code === "secret-exposure" && options.bundle.envExamplePath) {
      preparedFixes.push(
        `🔐 secret 清理这一步 → 运行时环境变量模板已经准备好了（${displayPath(options.bundle.envExamplePath)}）`
      );
      preparedOutcomes.push("🔐 把和当前工作流无关的 secrets 从 live runtime 环境里分出去");
      continue;
    }

    stillNeedsUser.push(violation);
  }

  lines.push(
    "",
    "🚧 你当前的运行态配置仍然比你刚批准的边界更宽。"
  );

  if (options.boundaryStatus.violations.length > 0) {
    lines.push(
      `🧮 在 ${options.boundaryStatus.violations.length} 个需要处理的点里，TraceRoot 已经先帮你准备好了 ${preparedFixes.length} 个。`
    );
  }

  if (preparedFixes.length > 0) {
    lines.push("", "✅ TraceRoot 已经先帮你准备好了这些修复：");

    for (const fix of preparedFixes) {
      lines.push(`- ${fix}`);
    }

    if (preparedOutcomes.length > 0) {
      lines.push("", "🎁 你把这套 bundle 应用进去后，TraceRoot 已经能先帮你做到：");
      for (const outcome of preparedOutcomes) {
        lines.push(`- ${outcome}`);
      }
    }
  }

  if (options.bundle.tapWrappers.length > 0) {
    lines.push("");

    lines.push(
      `🎬 动作审计现在已经开始盯住：${summarizeActionLabels(options.bundle.tapCoveredActions)}。`
    );
    if (options.bundle.tapInstalledCommands.length > 0) {
      lines.push(
        `   TraceRoot 已经自动接好 ${options.bundle.tapInstalledCommands.length} 个高风险动作入口。`
      );
    }
    lines.push("   之后这些动作一旦触发，TraceRoot 会立刻留下本地审计记录。");
    lines.push("   想回看 agent 做过什么，可以直接用：traceroot-audit logs");
    lines.push("   想只看今天最值得注意的动作，可以直接用：traceroot-audit logs --today");

    if (options.bundle.tapPendingActionsCount > 0 && options.bundle.tapPlanPath) {
      lines.push(
        `- 还有 ${options.bundle.tapPendingActionsCount} 类高风险动作暂时还没接好，TraceRoot 会继续把它们保留为待覆盖动作。`
      );
    }
  }

  if (stillNeedsUser.length > 0) {
    lines.push("", "👀 下面这些还需要你拍板：");

    for (const violation of stillNeedsUser.slice(0, 4)) {
      const icon =
        violation.severity === "critical"
          ? "🛑"
          : violation.severity === "high"
            ? "⚠️"
            : "ℹ️";
      lines.push(`- ${icon} ${violation.title}: ${violation.message}`);
    }
  } else {
    lines.push("", "👀 剩下的工作，基本就是把这套 bundle 真正应用到 live setup 里。");
  }

  const recommendations = [...new Set(options.boundaryStatus.violations.map((violation) => violation.recommendation))];
  if (recommendations.length > 0) {
    lines.push("", "🔧 最值得先做的事：");

    for (const recommendation of recommendations.slice(0, 3)) {
      lines.push(`- ${recommendation}`);
    }
  }

  if (options.bundle.composeOverridePath && options.bundle.composeSourcePath) {
    lines.push(
      "",
      "⚡ 要让这套更安全的运行态真正生效：",
      `- 按 ${displayPath(options.bundle.planPath)} 里的步骤，把新的 compose / env / manifest 同步到 live runtime。`
    );
  }

  lines.push(
    "",
    "🚀 如果你想继续让 TraceRoot 陪跑这个 agent：",
    "- traceroot-audit doctor --watch --interval 60"
  );

  return `${lines.join("\n")}\n`;
}

function renderDoctorResumeSummary(options: {
  target: string;
  profile: SavedHardeningProfile;
  reminder: string;
  boundaryStatus: ReturnType<typeof evaluateBoundaryStatus>;
}): string {
  const lines = [
    "TraceRoot Audit Doctor",
    "======================",
    "",
    "⚡ TraceRoot 已经直接续上了你上次的陪跑设置。",
    `🎯 继续陪跑：${displayUserPath(options.target)}`,
    `🧩 已批准工作流：${describeSavedWorkflows(options.profile)}`,
    `🔔 提醒方式：${options.reminder}`,
    ""
  ];

  if (options.boundaryStatus.aligned) {
    lines.push(
      "✅ 当前配置还在你批准的边界内。",
      "💓 TraceRoot 这次不会重新展开整套 Doctor，会直接继续盯着边界和高风险动作。"
    );
  } else {
    lines.push(
      `🚧 当前配置还比你批准的边界更宽（${options.boundaryStatus.violations.length} 个点）。`
    );

    const topViolations = options.boundaryStatus.violations.slice(0, 3);
    if (topViolations.length > 0) {
      lines.push("👀 现在最值得你留意的是：");

      for (const violation of topViolations) {
        const icon =
          violation.severity === "critical"
            ? "🛑"
            : violation.severity === "high"
              ? "⚠️"
              : "ℹ️";
        lines.push(`- ${icon} ${violation.title}: ${violation.message}`);
      }
    }

    const recommendations = [
      ...new Set(
        options.boundaryStatus.violations.map((violation) => violation.recommendation)
      )
    ];
    if (recommendations.length > 0) {
      lines.push("", "🔧 最值得先修的地方：");
      for (const recommendation of recommendations.slice(0, 3)) {
        lines.push(`- ${recommendation}`);
      }
    }

    lines.push(
      "",
      "💓 TraceRoot 这次不会重新生成整套 bundle，会先直接继续陪跑，并盯着这些边界变化。"
    );
  }

  lines.push(
    "",
    "📚 想看今天发生了什么，可以直接用：traceroot-audit logs --today"
  );

  return `${lines.join("\n")}\n`;
}

function selectionsFromSavedProfile(
  profile: SavedHardeningProfile
): HardeningSelections | null {
  if (!profile.selectedPolicies) {
    return null;
  }

  return {
    intentIds: profile.selectedIntents.map((intent) => intent.id),
    outboundApproval: profile.selectedPolicies.outboundApproval,
    filesystemScope: profile.selectedPolicies.filesystemScope,
    exposureMode: profile.selectedPolicies.exposureMode
  };
}

function describeSavedWorkflows(profile: SavedHardeningProfile): string {
  return profile.selectedIntents.map((intent) => intent.title).join("、");
}

function describeSavedReminder(options: {
  mode?: "local-only" | "webhook" | "channel";
  webhookUrl?: string;
  openclawChannel?: string;
  openclawTarget?: string;
}): string {
  if (options.mode === "local-only") {
    return "只保留本地审计时间线，不额外打扰你";
  }

  if (options.webhookUrl) {
    return "同一个 webhook 提醒入口";
  }

  if (options.openclawChannel && options.openclawTarget) {
    return `${displayNotifyChannel(options.openclawChannel)}（${options.openclawTarget}）`;
  }

  return "本地审计时间线";
}

function hasSavedReminderPreference(
  preferences:
    | {
        mode: "local-only" | "webhook" | "channel";
        notifications: {
          webhookUrl?: string;
          openclawChannel?: string;
          openclawTarget?: string;
        };
      }
    | null
): boolean {
  if (!preferences) {
    return false;
  }

  if (preferences.mode === "local-only") {
    return true;
  }

  if (preferences.mode === "webhook") {
    return Boolean(preferences.notifications.webhookUrl);
  }

  if (preferences.mode === "channel") {
    return Boolean(
      preferences.notifications.openclawChannel &&
        preferences.notifications.openclawTarget
    );
  }

  return false;
}

function renderHostDoctorWatchIntro(options: {
  candidateCount: number;
  suggestedNames: string[];
  reminder: string;
}): string {
  const lines = [
    "TraceRoot Audit Doctor",
    "======================",
    "",
    "🖥️ 这次 TraceRoot 会直接在这台机器上陪跑你常见的 agent / runtime 入口。",
    `📌 当前已经看到 ${options.candidateCount} 个可能真的会驱动 AI 动作的入口。`
  ];

  if (options.suggestedNames.length > 0) {
    lines.push(`🎯 现在最值得先盯住的是：${options.suggestedNames.join("、")}`);
  }

  lines.push(
    `🔔 提醒方式：${options.reminder}`,
    "",
    "💓 接下来如果这台机器上有 agent 开始做高风险动作，TraceRoot 会尽快提醒你，并把动作记进本地审计时间线。",
    "📚 想回看今天发生了什么，可以直接用：traceroot-audit logs --today",
    ""
  );

  return `${lines.join("\n")}\n`;
}

export function registerDoctorCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("doctor")
    .description(
      "The simplest guided path: find an agent surface, shrink it to what you actually want, and generate a safer bundle."
    )
    .argument("[target]", "directory or file to inspect; omit it to discover surfaces on this machine")
    .option(
      "--host",
      "force machine-level discovery first, even if you already know a target path"
    )
    .option(
      "--include-cwd",
      "when used with host discovery, also include the current working directory subtree"
    )
    .option(
      "--watch",
      "after preparing the safer bundle, keep watching this target for new drift"
    )
    .option(
      "--reconfigure",
      "ignore remembered target, boundary, and reminder settings, and walk through setup again"
    )
    .option(
      "--interval <seconds>",
      "when used with --watch, seconds between checks",
      "60"
    )
    .option(
      "--cycles <count>",
      "when used with --watch, number of watch cycles before exiting"
    )
    .option(
      "--notify-webhook <url>",
      "when used with --watch, also send high-risk action reminders to your webhook"
    )
    .option(
      "--notify-channel <channel>",
      "when used with --watch, also send high-risk action reminders through one of your connected OpenClaw chat channels"
    )
    .option(
      "--notify-target <target>",
      "where TraceRoot should send those reminders in the chosen chat channel"
    )
    .option(
      "--notify-account <account>",
      "optional OpenClaw account name to use for that chat channel"
    )
    .action(
      async (
        target: string | undefined,
        options: {
          host?: boolean;
          includeCwd?: boolean;
          watch?: boolean;
          reconfigure?: boolean;
          interval?: string;
          cycles?: string;
          notifyWebhook?: string;
          notifyChannel?: string;
          notifyTarget?: string;
          notifyAccount?: string;
        }
      ) => {
        const alreadyConfiguredNotification =
          Boolean(options.notifyWebhook) ||
          Boolean(options.notifyChannel) ||
          Boolean(options.notifyTarget) ||
          Boolean(options.notifyAccount);

        if (options.host && options.watch && !target) {
          const intervalSeconds = Number.parseInt(options.interval ?? "60", 10);
          const maxCycles = options.cycles
            ? Number.parseInt(options.cycles, 10)
            : undefined;

          if (!Number.isInteger(intervalSeconds) || intervalSeconds <= 0) {
            runtime.io.stderr("`--interval` must be a positive integer number of seconds.\n");
            runtime.exitCode = 1;
            return;
          }

          if (
            options.cycles !== undefined &&
            (!Number.isInteger(maxCycles) || (maxCycles ?? 0) <= 0)
          ) {
            runtime.io.stderr("`--cycles` must be a positive integer when provided.\n");
            runtime.exitCode = 1;
            return;
          }

          const hostDiscovery = await discoverHost({
            includeCwd: options.includeCwd
          });

          if (hostDiscovery.candidates.length === 0) {
            runtime.io.stdout(
              [
                "TraceRoot Audit Doctor",
                "======================",
                "",
                "暂时还没在这台机器上看到明显的 OpenClaw / runtime / skill 入口。",
                "等你的 runtime 真正跑起来以后，再重新运行 `traceroot-audit doctor --watch --host` 就可以了。"
              ].join("\n") + "\n"
            );
            return;
          }

          let notificationSettings = {
            webhookUrl: options.notifyWebhook,
            openclawChannel: options.notifyChannel,
            openclawTarget: options.notifyTarget,
            openclawAccount: options.notifyAccount
          };

          if (!alreadyConfiguredNotification) {
            const likelyChannels = await detectLikelyNotifyChannelsForTargets(
              hostDiscovery.candidates.slice(0, 6).map((candidate) => candidate.absolutePath)
            );
            const selection = await promptNotificationSelection(runtime, {
              likelyChannels
            });

            if (selection.mode === "webhook") {
              notificationSettings = {
                ...notificationSettings,
                webhookUrl: await runtime.prompter.input(
                  "🪝 TraceRoot 应该把提醒发到哪个 webhook？",
                  { allowEmpty: false }
                )
              };
            } else if (selection.mode === "channel") {
              notificationSettings = {
                ...notificationSettings,
                openclawChannel: selection.channel,
                openclawTarget: selection.target,
                openclawAccount: selection.account
              };
            }
          }

          runtime.io.stdout(
            renderHostDoctorWatchIntro({
              candidateCount: hostDiscovery.candidates.length,
              suggestedNames: hostDiscovery.candidates
                .slice(0, 3)
                .map((candidate) => candidate.displayPath),
              reminder: describeSavedReminder({
                mode:
                  notificationSettings.webhookUrl
                    ? "webhook"
                    : notificationSettings.openclawChannel && notificationSettings.openclawTarget
                      ? "channel"
                      : "local-only",
                webhookUrl: notificationSettings.webhookUrl,
                openclawChannel: notificationSettings.openclawChannel,
                openclawTarget: notificationSettings.openclawTarget
              })
            })
          );

          await runHostWatch({
            runtime,
            intervalSeconds,
            maxCycles,
            includeCwd: options.includeCwd,
            header: "TraceRoot Audit Doctor Watch",
            notifications: notificationSettings
          });
          return;
        }

        let preferredTarget = target;
        let offeredRecentTargetFastResume = false;
        let preConfirmedFastResume = false;
        if (!preferredTarget && !options.host) {
          const recentTarget = await loadRecentDoctorTarget();
          if (recentTarget) {
            if (options.reconfigure) {
              runtime.io.stdout(
                `🧠 TraceRoot 记得你上次陪跑的是：${recentTargetLabel(recentTarget)}。\n`
              );
              runtime.io.stdout(
                "↩️ 这次会在同一个位置重新帮你设置，不过不会沿用旧的边界和提醒方式。\n"
              );
              preferredTarget = recentTarget;
            }

            if (!options.reconfigure && options.watch && !alreadyConfiguredNotification) {
              try {
                const resolvedRecentTarget = await resolveTarget(recentTarget);
                const recentProfile = await loadHardeningProfile(
                  resolvedRecentTarget.rootDir
                );
                const recentSelections =
                  recentProfile.profile &&
                  selectionsFromSavedProfile(recentProfile.profile);
                const recentPreferences = await loadWatchPreferences(
                  resolvedRecentTarget.rootDir
                );

                if (recentSelections && hasSavedReminderPreference(recentPreferences)) {
                  runtime.io.stdout(
                    `🧠 TraceRoot 记得你上次陪跑的是：${recentTargetLabel(recentTarget)}。\n`
                  );
                  runtime.io.stdout(
                    `⚡ 上次那套方式 TraceRoot 也还记着：${describeSavedWorkflows(
                      recentProfile.profile!
                    )} + ${describeSavedReminder({
                      mode: recentPreferences!.mode,
                      webhookUrl: recentPreferences!.notifications.webhookUrl,
                      openclawChannel: recentPreferences!.notifications.openclawChannel,
                      openclawTarget: recentPreferences!.notifications.openclawTarget
                    })}。\n`
                  );
                  runtime.io.stdout(
                    "↩️ 这次 TraceRoot 会直接按上次那套方式续上；如果你想重新选工作流或提醒方式，可以加上 --reconfigure。\n"
                  );
                  offeredRecentTargetFastResume = true;
                  preferredTarget = recentTarget;
                  preConfirmedFastResume = true;
                }
              } catch {
                // fall back to the regular recent-target prompt below
              }
            }

            if (!preferredTarget && !offeredRecentTargetFastResume) {
              runtime.io.stdout(
                `🧠 TraceRoot 记得你上次陪跑的是：${recentTargetLabel(recentTarget)}。\n`
              );
              const reuseRecentTarget = await runtime.prompter.confirm(
                "这次要直接继续它吗？",
                true
              );

              if (reuseRecentTarget) {
                preferredTarget = recentTarget;
              }
            }
          }
        }

        const effectiveTarget = await resolveWizardTarget(runtime, {
          target: preferredTarget,
          host: options.host,
          includeCwd: options.includeCwd,
          emptyStateTitle: "TraceRoot Audit Doctor",
          emptyStateHint:
            "TraceRoot 暂时还没在常见位置里看到明显的 OpenClaw / runtime / skill 入口。\n如果你已经知道目录，直接运行 `traceroot-audit doctor /path/to/project` 就可以从那里开始。",
          chooseTargetQuestion:
            "🧭 TraceRoot 找到了这些可能真的会驱动 AI 动作的入口。你想先让 Doctor 处理哪一个？"
        });

        if (!effectiveTarget) {
          return;
        }

        await saveRecentDoctorTarget(effectiveTarget);

        const resolvedTarget = await resolveTarget(effectiveTarget);
        const existingProfile = await loadHardeningProfile(resolvedTarget.rootDir);
        const savedPreferences = !alreadyConfiguredNotification && !options.reconfigure
          ? await loadWatchPreferences(resolvedTarget.rootDir)
          : null;
        let selections = !options.reconfigure && existingProfile.profile
          ? selectionsFromSavedProfile(existingProfile.profile)
          : null;
        const canFastResume =
          !options.reconfigure &&
          Boolean(options.watch) &&
          Boolean(selections) &&
          hasSavedReminderPreference(savedPreferences);
        let fastResume = preConfirmedFastResume;

        if (canFastResume && !preConfirmedFastResume) {
          runtime.io.stdout(
            `⚡ 上次那套方式 TraceRoot 也还记着：${describeSavedWorkflows(
              existingProfile.profile!
            )} + ${describeSavedReminder({
              mode: savedPreferences!.mode,
              webhookUrl: savedPreferences!.notifications.webhookUrl,
              openclawChannel: savedPreferences!.notifications.openclawChannel,
              openclawTarget: savedPreferences!.notifications.openclawTarget
            })}。\n`
          );
          runtime.io.stdout(
            "↩️ 这次 TraceRoot 会直接按上次那套方式续上；如果你想重新选工作流或提醒方式，可以加上 --reconfigure。\n"
          );
          fastResume = true;
        }

        if (selections && !fastResume) {
          runtime.io.stdout(
            `🧠 TraceRoot 记得你上次批准过这些工作流：${describeSavedWorkflows(
              existingProfile.profile!
            )}。\n`
          );
          const reuseSelections = await runtime.prompter.confirm(
            "这次要继续沿用这套边界吗？",
            true
          );

          if (!reuseSelections) {
            selections = null;
          }
        }

        if (!selections) {
          selections = await promptHardeningSelections(runtime, effectiveTarget);
        }

        let plan: Awaited<ReturnType<typeof buildHardeningPlan>> | null = null;
        let savedProfile: Awaited<ReturnType<typeof loadHardeningProfile>> | null =
          existingProfile;
        let boundaryStatus: ReturnType<typeof evaluateBoundaryStatus>;

        if (fastResume) {
          const currentState = await buildCurrentHardeningState(
            effectiveTarget,
            selections.intentIds
          );
          boundaryStatus = evaluateBoundaryStatus(savedProfile.profile!, currentState);

          runtime.io.stdout(
            renderDoctorResumeSummary({
              target: effectiveTarget,
              profile: savedProfile.profile!,
              reminder: describeSavedReminder({
                mode: savedPreferences!.mode,
                webhookUrl: savedPreferences!.notifications.webhookUrl,
                openclawChannel: savedPreferences!.notifications.openclawChannel,
                openclawTarget: savedPreferences!.notifications.openclawTarget
              }),
              boundaryStatus
            })
          );
        } else {
          plan = await buildHardeningPlan(effectiveTarget, selections);
          runtime.io.stdout(
            "📦 TraceRoot 现在会直接把这套更安全的补丁包先准备好，后面你需要时就能直接用。\n"
          );

          await writeHardeningFiles(plan, {
            manifestFormat: recommendedManifestFormat(plan.manifestPath)
          });

          savedProfile = await loadHardeningProfile(plan.rootDir);
          if (!savedProfile.profile) {
            runtime.io.stderr(
              `Saved boundary could not be loaded after hardening: ${savedProfile.error ?? "unknown error"}\n`
            );
            runtime.exitCode = 1;
            return;
          }

          const bundle = await writeApplyBundle({
            rootDir: plan.rootDir,
            profile: savedProfile.profile,
            manifestPathHint: plan.manifestPath
          });
          const currentState = await buildCurrentHardeningState(
            effectiveTarget,
            selections.intentIds
          );
          boundaryStatus = evaluateBoundaryStatus(savedProfile.profile, currentState);

          runtime.io.stdout(
            renderDoctorSummary({
              target: effectiveTarget,
              plan,
              selectedWorkflows: plan.selectedProfiles.map(
                (profile) => `${profile.icon} ${profile.title}`
              ),
              bundle,
              boundaryStatus
            })
          );
        }

        if (!options.watch) {
          return;
        }

        const intervalSeconds = Number.parseInt(options.interval ?? "60", 10);
        const maxCycles = options.cycles
          ? Number.parseInt(options.cycles, 10)
          : undefined;

        if (!Number.isInteger(intervalSeconds) || intervalSeconds <= 0) {
          runtime.io.stderr("`--interval` must be a positive integer number of seconds.\n");
          runtime.exitCode = 1;
          return;
        }

        if (
          options.cycles !== undefined &&
          (!Number.isInteger(maxCycles) || (maxCycles ?? 0) <= 0)
        ) {
          runtime.io.stderr("`--cycles` must be a positive integer when provided.\n");
          runtime.exitCode = 1;
          return;
        }

        runtime.io.stdout(
          "\n💓 TraceRoot 现在会继续陪跑这个 agent，并盯着边界和高风险动作。\n\n"
        );

        let notificationSettings = {
          webhookUrl: options.notifyWebhook,
          openclawChannel: options.notifyChannel,
          openclawTarget: options.notifyTarget,
          openclawAccount: options.notifyAccount
        };

        if (!alreadyConfiguredNotification) {
          if (savedPreferences?.mode === "local-only") {
            if (!fastResume) {
              runtime.io.stdout(
                "\n🧠 TraceRoot 记得你上次只保留本地审计时间线，这次也会继续保持安静，不额外打扰你。\n"
              );
            }
          } else if (savedPreferences?.notifications.webhookUrl) {
            notificationSettings = {
              ...notificationSettings,
              webhookUrl: savedPreferences.notifications.webhookUrl
            };
            if (!fastResume) {
              runtime.io.stdout(
              "\n🧠 TraceRoot 记得你上次想把高风险提醒发到同一个 webhook，这次会继续沿用。\n"
              );
            }
          } else if (
            savedPreferences?.notifications.openclawChannel &&
            savedPreferences.notifications.openclawTarget
          ) {
            notificationSettings = {
              ...notificationSettings,
              openclawChannel: savedPreferences.notifications.openclawChannel,
              openclawTarget: savedPreferences.notifications.openclawTarget,
              openclawAccount: savedPreferences.notifications.openclawAccount
            };
            if (!fastResume) {
              runtime.io.stdout(
              `\n🧠 TraceRoot 记得你上次把提醒发到 ${displayNotifyChannel(
                savedPreferences.notifications.openclawChannel
              )}（${savedPreferences.notifications.openclawTarget}），这次会继续沿用。\n`
              );
            }
          }
        }

        if (
          !alreadyConfiguredNotification &&
          savedPreferences?.mode !== "local-only" &&
          !notificationSettings.webhookUrl &&
          !notificationSettings.openclawChannel &&
          !notificationSettings.openclawTarget
        ) {
          const selection = await promptNotificationSelection(runtime, {
            target: effectiveTarget
          });

          if (selection.mode === "webhook") {
            notificationSettings = {
              ...notificationSettings,
              webhookUrl: await runtime.prompter.input(
                "🪝 TraceRoot 应该把提醒发到哪个 webhook？",
                { allowEmpty: false }
              )
            };
          } else if (selection.mode === "channel") {
            notificationSettings = {
              ...notificationSettings,
              openclawChannel: selection.channel,
              openclawTarget: selection.target,
              openclawAccount: selection.account
            };
          }
        }

        const savedReminderMode =
          notificationSettings.webhookUrl
            ? "webhook"
            : notificationSettings.openclawChannel && notificationSettings.openclawTarget
              ? "channel"
              : "local-only";

        await saveWatchPreferences(resolvedTarget.rootDir, {
          version: 1,
          updatedAt: new Date().toISOString(),
          mode: savedReminderMode,
          notifications: notificationSettings
        });

        await runTargetWatch({
          runtime,
          target: effectiveTarget,
          intervalSeconds,
          maxCycles,
          header: "TraceRoot Audit Doctor Watch",
          compactStart: true,
          notifications: notificationSettings
        });
      }
    );
}
