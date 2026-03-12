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
    "📉 Boundary shrink preview:",
    `- Today: ${currentPower}`,
    `- Approved: ${approvedPower}`,
    `- Approval policy: ${options.plan.approvalPolicy}`,
    `- File write policy: ${options.plan.fileWritePolicy}`,
    `- Exposure policy: ${options.plan.exposurePolicy}`,
    "",
    "✨ We already prepared a safer bundle for you:",
    `- 📜 Recommended manifest: ${displayPath(options.bundle.manifestPath)}`,
    `- 🧭 Apply plan: ${displayPath(options.bundle.planPath)}`
  ];

  if (options.bundle.envExamplePath) {
    lines.push(`- 🔐 Runtime env template: ${displayPath(options.bundle.envExamplePath)}`);
  }

  if (options.bundle.composeOverridePath) {
    lines.push(`- 🌐 Compose override: ${displayPath(options.bundle.composeOverridePath)}`);
  }

  if (options.boundaryStatus.aligned) {
    lines.push(
      "",
      "✅ Good news: your current setup already matches the approved boundary.",
      `💓 Keep watching it with: traceroot-audit doctor "${options.target}" --watch --interval 60`
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
        `🌐 Public exposure → compose override ready (${displayPath(options.bundle.composeOverridePath)})`
      );
      preparedOutcomes.push("🌐 keep the runtime on localhost instead of exposing it more broadly");
      continue;
    }

    if (violation.code === "missing-confirmation") {
      preparedFixes.push(
        `📜 Missing approval guard → hardened manifest ready (${displayPath(options.bundle.manifestPath)})`
      );
      preparedOutcomes.push("📜 enforce confirmation before side-effecting actions");
      continue;
    }

    if (violation.code === "secret-exposure" && options.bundle.envExamplePath) {
      preparedFixes.push(
        `🔐 Secret cleanup → runtime env template ready (${displayPath(options.bundle.envExamplePath)})`
      );
      preparedOutcomes.push("🔐 split unrelated secrets out of the live runtime env");
      continue;
    }

    stillNeedsUser.push(violation);
  }

  lines.push(
    "",
    "🚧 Your live setup is still broader than the boundary you just approved."
  );

  if (options.boundaryStatus.violations.length > 0) {
    lines.push(
      `🧮 TraceRoot already prepared ${preparedFixes.length} of ${options.boundaryStatus.violations.length} needed fixes.`
    );
  }

  if (preparedFixes.length > 0) {
    lines.push("", "✅ TraceRoot already prepared fixes for you:");

    for (const fix of preparedFixes) {
      lines.push(`- ${fix}`);
    }

    if (preparedOutcomes.length > 0) {
      lines.push("", "🎁 If you apply the bundle, TraceRoot will already help you:");
      for (const outcome of preparedOutcomes) {
        lines.push(`- ${outcome}`);
      }
    }
  }

  if (stillNeedsUser.length > 0) {
    lines.push("", "👀 Still needs your decision:");

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
    lines.push("", "👀 The remaining work is mostly applying the bundle to your live setup.");
  }

  const recommendations = [...new Set(options.boundaryStatus.violations.map((violation) => violation.recommendation))];
  if (recommendations.length > 0) {
    lines.push("", "🔧 Start here:");

    for (const recommendation of recommendations.slice(0, 3)) {
      lines.push(`- ${recommendation}`);
    }
  }

  if (options.bundle.composeOverridePath && options.bundle.composeSourcePath) {
    lines.push(
      "",
      "⚡ Apply right now:",
      `- cd "${options.plan.rootDir}"`,
      `- docker compose -f ${path.basename(options.bundle.composeSourcePath)} -f ${path.basename(options.bundle.composeOverridePath)} up -d`
    );
  }

  lines.push(
    "",
    "🚀 Best next command:",
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
