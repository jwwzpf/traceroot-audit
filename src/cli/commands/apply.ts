import { Command } from "commander";

import { loadHardeningProfile } from "../../hardening/profile";
import { writeApplyBundle } from "../../hardening/apply";
import { loadManifest } from "../../manifest/loader";
import { resolveTarget } from "../../utils/files";
import { displayUserPath } from "../../utils/paths";
import { summarizeActionLabels } from "../../audit/presentation";

import type { CliRuntime } from "../index";

export function registerApplyCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("apply")
    .description(
      "Generate safer companion patch files from an approved hardening profile."
    )
    .argument("[target]", "directory or file whose approved profile should be applied", ".")
    .action(async (target: string) => {
      const resolvedTarget = await resolveTarget(target);
      const hardeningProfileResult = await loadHardeningProfile(resolvedTarget.rootDir);

      if (!hardeningProfileResult.profile) {
        runtime.io.stderr(
          [
            "No saved hardening profile was found for this target.",
            "Run `traceroot-audit harden` first so TraceRoot can learn the workflows and boundary you approved."
          ].join("\n") + "\n"
        );
        runtime.exitCode = 1;
        return;
      }

      const manifestLoadResult = await loadManifest(resolvedTarget.rootDir);

      const bundle = await writeApplyBundle({
        rootDir: resolvedTarget.rootDir,
        profile: hardeningProfileResult.profile,
        manifestPathHint: manifestLoadResult.manifestPath
      });

      const lines = [
        "TraceRoot Audit Apply",
        "=====================",
        "",
        `🎯 当前处理位置：${displayUserPath(resolvedTarget.rootDir)}`,
        `🛡️ 你刚批准的工作流：${hardeningProfileResult.profile.selectedIntents
          .map((intent) => intent.title)
          .join(", ")}`,
        "",
        "✨ TraceRoot 已经先帮你准备好了这些文件：",
        `- 📜 更小权限的 manifest 建议：${bundle.manifestPath}`,
        `- 🧭 应用步骤说明：${bundle.planPath}`
      ];

      if (bundle.envExamplePath) {
        lines.push(`- 🔐 更干净的运行时环境变量模板：${bundle.envExamplePath}`);
      }

      if (bundle.composeOverridePath) {
        lines.push(`- 🌐 更安全的 compose 覆盖文件：${bundle.composeOverridePath}`);
      }

      lines.push("", "🚀 你现在最值得先做的事：");

      if (bundle.movedSecrets.length > 0) {
        lines.push(
          `- 先把这些和当前工作流无关的 secrets 挪出运行时环境变量：${bundle.movedSecrets.join(", ")}`
        );
      }

      if (bundle.composeOverridePath && bundle.composeSourcePath) {
        lines.push(
          `- 要让更安全的网络边界真正生效，按 ${displayUserPath(bundle.planPath, { cwd: resolvedTarget.rootDir })} 里的步骤把新的 compose 配置同步到 live runtime。`
        );
      } else {
        lines.push("- 检查一下 runtime 的网络暴露范围，能只留在本机就尽量只留在本机。");
      }

      if (bundle.tapPlanPath && bundle.tapWrappers.length > 0) {
        lines.push(
          `- 动作审计已经开始盯住这些高风险动作：${summarizeActionLabels(bundle.tapCoveredActions)}。`
        );
        lines.push(
          `- 以后想回看 agent 刚才到底做了什么，可以直接运行：traceroot-audit logs "${displayUserPath(resolvedTarget.rootDir)}"`
        );

        if (bundle.tapPendingActionsCount > 0) {
          lines.push(
            `- 还有 ${bundle.tapPendingActionsCount} 类高风险动作暂时还没接好，TraceRoot 会继续把它们保留为待覆盖动作。`
          );
        }
      }

      lines.push(
        `- 最后把你当前正在使用的 manifest 和 ${displayUserPath(bundle.manifestPath, { cwd: resolvedTarget.rootDir })} 对照一下，把更小的能力范围同步进去。`
      );

      runtime.io.stdout(`${lines.join("\n")}\n`);
    });
}
