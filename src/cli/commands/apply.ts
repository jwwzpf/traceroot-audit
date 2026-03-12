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

      if (bundle.tapPlanPath && bundle.tapWrapperDir) {
        lines.push(`- 🎬 动作审计说明：${bundle.tapPlanPath}`);
        lines.push(`- 🧷 TraceRoot 准备好的审计接入文件：${bundle.tapWrapperDir}`);
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
        if (bundle.tapInstalledCommands.length > 0) {
          lines.push(
            `- 动作审计这一步，TraceRoot 已经先帮你接好了 ${bundle.tapInstalledCommands.length} 个常见启动命令。以后你还是照常运行 ${bundle.tapInstalledCommands
              .filter((command) => command.kind === "npm-script")
              .map((command) => `npm run ${command.name}`)
              .join("、")} 就行。`
          );

          if (bundle.tapInstallBackupPath) {
            lines.push(
              `- 我们也帮你把原来的 package.json 备份好了：${bundle.tapInstallBackupPath}`
            );
          }

          lines.push(
            `- 如果你想看看 TraceRoot 是怎么帮你接上的，可以打开 ${bundle.tapPlanPath}。`
          );
        } else {
          lines.push(
            `- 如果你平时会运行发邮件、发帖、下单这类高风险动作，请打开 ${bundle.tapPlanPath}。TraceRoot 已经帮你准备好了 ${bundle.tapWrappers.length} 个接入文件；能自动接的常见启动命令，我们之后也会继续替你自动接上。`
          );
        }
      }

      lines.push(
        `- 最后把你当前正在使用的 manifest 和 ${bundle.manifestPath} 对照一下，把更小的能力范围同步进去。`
      );

      runtime.io.stdout(`${lines.join("\n")}\n`);
    });
}
