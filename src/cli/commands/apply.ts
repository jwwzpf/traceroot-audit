import { Command } from "commander";

import { loadHardeningProfile } from "../../hardening/profile";
import { writeApplyBundle } from "../../hardening/apply";
import { loadManifest } from "../../manifest/loader";
import { resolveTarget } from "../../utils/files";

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
        `🎯 Target: ${target}`,
        `🛡️ Approved workflows: ${hardeningProfileResult.profile.selectedIntents
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
          `- 用更安全的 compose 配置重新启动 runtime：docker compose -f ${bundle.composeSourcePath} -f ${bundle.composeOverridePath} up -d`
        );
      } else {
        lines.push("- 检查一下 runtime 的网络暴露范围，能只留在本机就尽量只留在本机。");
      }

      if (bundle.tapPlanPath && bundle.tapWrappers.length > 0) {
        lines.push(
          `- 动作审计已经开始覆盖 ${bundle.tapCoveredActionsCount} 个高风险动作。之后这些动作一旦触发，TraceRoot 就会留下可追溯的审计记录。`
        );
        lines.push(
          `- 想回看 agent 刚才到底做了什么，可以直接运行：traceroot-audit logs "${target}"`
        );

        if (bundle.tapPendingActionsCount > 0) {
          lines.push(
            `- 还有 ${bundle.tapPendingActionsCount} 个高风险动作暂时没有自动接上。需要时再打开 ${bundle.tapPlanPath} 看细节就行。`
          );
        }
      }

      lines.push(
        `- 最后把你当前正在使用的 manifest 和 ${bundle.manifestPath} 对照一下，把更小的能力范围同步进去。`
      );

      runtime.io.stdout(`${lines.join("\n")}\n`);
    });
}
