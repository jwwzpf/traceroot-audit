import { Command } from "commander";

import {
  buildHardeningPlan,
  recommendedManifestFormat,
  type HardeningSelections
} from "../../hardening/analysis";
import { writeHardeningFiles } from "../../hardening/writer";
import {
  promptHardeningSelections,
  resolveWizardTarget
} from "../../hardening/wizard";
import { renderHardeningHumanOutput } from "../../core/output";
import type { CliRuntime } from "../index";

export function registerHardenCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("harden")
    .description(
      "Interactive wizard that shrinks an agent surface to the workflows you actually want."
    )
    .argument("[target]", "directory or file to harden", ".")
    .option(
      "--host",
      "discover likely OpenClaw/runtime surfaces on this machine, then let you choose one"
    )
    .option(
      "--include-cwd",
      "when used with --host, also include the current working directory subtree in host discovery"
    )
    .action(
      async (
        target: string,
        options: {
          host?: boolean;
          includeCwd?: boolean;
        }
      ) => {
        const effectiveTarget = await resolveWizardTarget(runtime, {
          target,
          host: options.host,
          includeCwd: options.includeCwd,
          emptyStateTitle: "TraceRoot Audit Hardening",
          emptyStateHint:
            "TraceRoot 暂时还没在常见位置里看到明显的 OpenClaw / runtime 入口。\n如果你已经知道目录，直接在那个项目里运行 `traceroot-audit discover .` 就行。",
          chooseTargetQuestion:
            "🧭 TraceRoot 找到了这些可能会真正驱动 AI 动作的入口。你想先收紧哪一个？"
        });

        if (!effectiveTarget) {
          return;
        }

        const selections: HardeningSelections = await promptHardeningSelections(runtime, target);
        const plan = await buildHardeningPlan(effectiveTarget, selections);

        runtime.io.stdout(renderHardeningHumanOutput(plan));

        const shouldWrite = await runtime.prompter.confirm(
          "📄 Generate hardening companion files in this target directory?",
          true
        );

        if (!shouldWrite) {
          runtime.io.stdout("Skipped file generation.\n");
          return;
        }

        const writeResult = await writeHardeningFiles(plan, {
          manifestFormat: recommendedManifestFormat(plan.manifestPath)
        });

        runtime.io.stdout(
          [
            "",
            "TraceRoot Audit Hardening Files",
            "===============================",
            "",
            `✨ Report: ${writeResult.reportPath}`,
            `🧩 Profile: ${writeResult.profilePath}`,
            `📜 Manifest suggestion: ${writeResult.manifestPath}`,
            "",
            "Next steps:",
            `- Run \`traceroot-audit apply "${effectiveTarget}"\` to generate a safer patch bundle.`,
            "- Review the generated manifest suggestion and compare it with your current setup.",
            `- Re-run \`traceroot-audit doctor "${effectiveTarget}" --watch --interval 60\` after you apply the changes.`
          ].join("\n") + "\n"
        );
      }
    );
}
