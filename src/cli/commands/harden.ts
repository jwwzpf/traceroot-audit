import { Command } from "commander";

import {
  buildHardeningPlan,
  recommendedManifestFormat,
  type ExposureMode,
  type FilesystemScope,
  type HardeningSelections,
  type OutboundApprovalMode
} from "../../hardening/analysis";
import { hardeningIntentProfiles, type HardeningIntentId } from "../../hardening/profiles";
import { writeHardeningFiles } from "../../hardening/writer";
import { discoverHost } from "../../core/discovery";
import { renderHardeningHumanOutput } from "../../core/output";
import { surfaceLabel } from "../../core/surfaces";

import type { CliChoice, CliRuntime } from "../index";

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
        let effectiveTarget = target;

        if (options.host) {
          const hostDiscovery = await discoverHost({
            includeCwd: options.includeCwd ?? false
          });

          if (hostDiscovery.candidates.length === 0) {
            runtime.io.stdout(
              [
                "TraceRoot Audit Hardening",
                "=========================",
                "",
                "No likely OpenClaw/runtime surfaces were found in the common locations we checked.",
                "Run `traceroot-audit discover .` inside a specific project if you already know where it lives."
              ].join("\n") + "\n"
            );
            return;
          }

          const selectedPath = await runtime.prompter.chooseOne(
            "🧭 We found these likely AI action surfaces. Which one do you want to harden?",
            hostDiscovery.candidates.map((candidate) => ({
              value: candidate.absolutePath,
              label: `${candidate.displayPath} (${surfaceLabel(candidate.surface.kind)})`,
              hint: candidate.surface.reasons[0]
            }))
          );

          effectiveTarget = selectedPath;
        }

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

        const selections: HardeningSelections = {
          intentIds,
          outboundApproval,
          filesystemScope,
          exposureMode
        };
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
            "- Review the generated manifest suggestion and compare it with your current setup.",
            "- Move unrelated secrets out of the agent runtime env.",
            "- Re-run `traceroot-audit scan` after you apply the changes."
          ].join("\n") + "\n"
        );
      }
    );
}
