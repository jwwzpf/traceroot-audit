import { Command } from "commander";

import { buildCurrentHardeningState, buildHardeningPlan } from "../../hardening/analysis";
import { writeApplyBundle } from "../../hardening/apply";
import { evaluateBoundaryStatus } from "../../hardening/boundary";
import { loadHardeningProfile } from "../../hardening/profile";
import { writeHardeningFiles } from "../../hardening/writer";
import { promptHardeningSelections, resolveWizardTarget } from "../../hardening/wizard";
import { recommendedManifestFormat } from "../../hardening/analysis";

import type { CliRuntime } from "../index";

function renderDoctorSummary(options: {
  target: string;
  selectedWorkflows: string[];
  bundle: Awaited<ReturnType<typeof writeApplyBundle>>;
  boundaryStatus: ReturnType<typeof evaluateBoundaryStatus>;
}): string {
  const lines = [
    "TraceRoot Audit Doctor",
    "======================",
    "",
    `🎯 Target: ${options.target}`,
    `🧩 Approved workflows: ${options.selectedWorkflows.join(", ")}`,
    "",
    "✨ We already prepared a safer bundle for you:",
    `- 📜 Recommended manifest: ${options.bundle.manifestPath}`,
    `- 🧭 Apply plan: ${options.bundle.planPath}`
  ];

  if (options.bundle.envExamplePath) {
    lines.push(`- 🔐 Runtime env template: ${options.bundle.envExamplePath}`);
  }

  if (options.bundle.composeOverridePath) {
    lines.push(`- 🌐 Compose override: ${options.bundle.composeOverridePath}`);
  }

  if (options.boundaryStatus.aligned) {
    lines.push(
      "",
      "✅ Good news: your current setup already matches the approved boundary.",
      `💓 Keep watching it with: traceroot-audit guard "${options.target}" --interval 60`
    );

    return `${lines.join("\n")}\n`;
  }

  lines.push(
    "",
    "🚧 Your live setup is still broader than the boundary you just approved."
  );

  for (const violation of options.boundaryStatus.violations.slice(0, 4)) {
    const icon =
      violation.severity === "critical"
        ? "🛑"
        : violation.severity === "high"
          ? "⚠️"
          : "ℹ️";
    lines.push(`- ${icon} ${violation.title}: ${violation.message}`);
  }

  const recommendations = [...new Set(options.boundaryStatus.violations.map((violation) => violation.recommendation))];
  if (recommendations.length > 0) {
    lines.push("", "🔧 Start with these fixes:");

    for (const recommendation of recommendations.slice(0, 3)) {
      lines.push(`- ${recommendation}`);
    }
  }

  lines.push(
    "",
    "🚀 Best next command:",
    `- traceroot-audit guard "${options.target}" --interval 60`
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
    .action(
      async (
        target: string | undefined,
        options: {
          host?: boolean;
          includeCwd?: boolean;
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
            "🛠️ TraceRoot is preparing a smaller approved boundary and safer patch bundle..."
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
            selectedWorkflows: plan.selectedProfiles.map(
              (profile) => `${profile.icon} ${profile.title}`
            ),
            bundle,
            boundaryStatus
          })
        );
      }
    );
}
