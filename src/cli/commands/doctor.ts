import path from "node:path";

import { Command } from "commander";

import { buildCurrentHardeningState, buildHardeningPlan } from "../../hardening/analysis";
import { writeApplyBundle } from "../../hardening/apply";
import { evaluateBoundaryStatus } from "../../hardening/boundary";
import { loadHardeningProfile } from "../../hardening/profile";
import { writeHardeningFiles } from "../../hardening/writer";
import { promptHardeningSelections, resolveWizardTarget } from "../../hardening/wizard";
import { recommendedManifestFormat } from "../../hardening/analysis";
import { runTargetWatch } from "../watch";

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

  const lines = [
    "TraceRoot Audit Doctor",
    "======================",
    "",
    `🎯 Target: ${options.target}`,
    `🧩 Approved workflows: ${options.selectedWorkflows.join(", ")}`,
    "",
    "📉 权限收缩预览：",
    `- 现在：${currentPower}`,
    `- 收紧后：${approvedPower}`,
    `- 审批方式：${options.plan.approvalPolicy}`,
    `- 文件写入范围：${options.plan.fileWritePolicy}`,
    `- 网络暴露范围：${options.plan.exposurePolicy}`,
    "",
    "✨ TraceRoot 已经先帮你准备好了这些内容：",
    `- 📜 更小权限的 manifest 建议：${displayPath(options.bundle.manifestPath)}`,
    `- 🧭 应用步骤说明：${displayPath(options.bundle.planPath)}`
  ];

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
      `💓 如果你想继续陪跑守护它，可以运行：traceroot-audit doctor "${options.target}" --watch --interval 60`
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
    "🚧 你当前的 live 配置仍然比你刚批准的边界更宽。"
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
      `🎬 动作审计已经开始覆盖 ${options.bundle.tapCoveredActionsCount} 个高风险动作。`
    );
    lines.push("   之后这些动作一旦触发，TraceRoot 会立刻留下本地审计记录。");
    lines.push(`   你之后可以直接用：traceroot-audit logs "${options.target}"`);

    if (options.bundle.tapPendingActionsCount > 0 && options.bundle.tapPlanPath) {
      lines.push(
        `- 还有 ${options.bundle.tapPendingActionsCount} 个高风险动作暂时没自动接上，TraceRoot 已经把它们记在 ${displayPath(options.bundle.tapPlanPath)} 里了。`
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
      "⚡ 现在就可以这样做：",
      `- cd "${options.plan.rootDir}"`,
      `- docker compose -f ${path.basename(options.bundle.composeSourcePath)} -f ${path.basename(options.bundle.composeOverridePath)} up -d`
    );
  }

  lines.push(
    "",
    "🚀 下一步最适合这样跑：",
    `- traceroot-audit doctor "${options.target}" --watch --interval 60`
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
      "--interval <seconds>",
      "when used with --watch, seconds between checks",
      "60"
    )
    .option(
      "--cycles <count>",
      "when used with --watch, number of watch cycles before exiting"
    )
    .action(
      async (
        target: string | undefined,
        options: {
          host?: boolean;
          includeCwd?: boolean;
          watch?: boolean;
          interval?: string;
          cycles?: string;
        }
      ) => {
        const effectiveTarget = await resolveWizardTarget(runtime, {
          target,
          host: options.host,
          includeCwd: options.includeCwd,
          emptyStateTitle: "TraceRoot Audit Doctor",
          emptyStateHint:
            "We could not find an obvious OpenClaw/runtime/skill surface in the common locations we checked.\nIf you already know the directory, run `traceroot-audit doctor /path/to/project`.",
          chooseTargetQuestion:
            "🧭 We found these likely AI action surfaces. Which one do you want TraceRoot Doctor to work on?"
        });

        if (!effectiveTarget) {
          return;
        }

        const selections = await promptHardeningSelections(runtime);
        const plan = await buildHardeningPlan(effectiveTarget, selections);

        runtime.io.stdout(
          [
            `🎯 Target: ${effectiveTarget}`,
            `🧭 Surface: ${plan.surfaceLabel}`,
            `🧩 Workflows: ${plan.selectedProfiles.map((profile) => `${profile.icon} ${profile.title}`).join(", ")}`,
            "🛠️ TraceRoot 正在帮你收紧边界，并准备更安全的补丁包..."
          ].join("\n") + "\n"
        );

        const shouldWrite = await runtime.prompter.confirm(
          "📦 Generate the safer bundle now?",
          true
        );

        if (!shouldWrite) {
          runtime.io.stdout("Stopped before generating the safer bundle.\n");
          return;
        }

        await writeHardeningFiles(plan, {
          manifestFormat: recommendedManifestFormat(plan.manifestPath)
        });

        const savedProfile = await loadHardeningProfile(plan.rootDir);
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
        const boundaryStatus = evaluateBoundaryStatus(savedProfile.profile, currentState);

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
          "\n💓 Doctor is staying with you and will keep watching this boundary now.\n\n"
        );

        await runTargetWatch({
          runtime,
          target: effectiveTarget,
          intervalSeconds,
          maxCycles,
          header: "TraceRoot Audit Doctor Watch",
          compactStart: true
        });
      }
    );
}
