import { Command, Option } from "commander";

import { discoverHost } from "../../core/discovery";
import {
  createHostSnapshot,
  createScanSnapshot,
  diffHostSnapshots,
  diffScanSnapshots
} from "../../core/guard";
import { scanTarget } from "../../core/scanner";

import type { CliRuntime } from "../index";

interface GuardOptions {
  host?: boolean;
  includeCwd?: boolean;
  interval: string;
  cycles?: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function timestamp(): string {
  return new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

export function registerGuardCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("guard")
    .description(
      "Keep watching a target or this machine for new agent surfaces and risk changes."
    )
    .argument("[target]", "directory or file to guard", ".")
    .option(
      "--host",
      "watch common agent/runtime locations on this machine instead of only one target"
    )
    .option(
      "--include-cwd",
      "when used with --host, also include the current working directory subtree in guard mode"
    )
    .addOption(
      new Option("--interval <seconds>", "seconds between checks")
        .default("30")
    )
    .addOption(
      new Option("--cycles <count>", "number of guard cycles before exiting")
    )
    .action(async (target: string, options: GuardOptions) => {
      const intervalSeconds = Number.parseInt(options.interval, 10);
      const maxCycles = options.cycles ? Number.parseInt(options.cycles, 10) : undefined;

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

      if (options.host) {
        const initialDiscovery = await discoverHost({
          includeCwd: options.includeCwd ?? false
        });
        let previousSnapshot = createHostSnapshot(initialDiscovery);
        const initialBestFirst = initialDiscovery.candidates.filter(
          (candidate) => candidate.tier === "best-first"
        );
        const initialSuggested = (
          initialBestFirst.length > 0 ? initialBestFirst : initialDiscovery.candidates
        ).slice(0, 3);

        const initialLines = [
          "TraceRoot Audit Guard",
          "=====================",
          "",
          "🖥️ Mode: host",
          `⏱️ Interval: every ${intervalSeconds}s`,
          `📌 Surfaces currently visible: ${initialDiscovery.candidates.length}`,
          initialBestFirst.length > 0
            ? `🎯 Best first right now: ${initialBestFirst
                .map((candidate) => candidate.displayPath)
                .slice(0, 3)
                .join(", ")}`
            : "🧭 No best-first surfaces right now; showing the top possible ones instead.",
          "",
          "💓 Guard is watching for:",
          "- new AI action surfaces",
          "- surfaces promoted into best-first priority",
          "- surfaces disappearing from the machine-level view",
          ""
        ];

        if (initialSuggested.length > 0) {
          initialLines.push("🚀 What you can do right now:");

          for (const candidate of initialSuggested) {
            initialLines.push(
              `- ${candidate.displayPath} → ${candidate.recommendedActionLabel}`,
              `  ${candidate.recommendedCommand}`
            );
          }

          initialLines.push("");
        }

        runtime.io.stdout(`${initialLines.join("\n")}\n`);

        const totalCycles = maxCycles ?? Number.POSITIVE_INFINITY;

        for (let cycle = 1; cycle <= totalCycles; cycle += 1) {
          if (cycle > 1) {
            await sleep(intervalSeconds * 1000);
          }

          const latestDiscovery = await discoverHost({
            includeCwd: options.includeCwd ?? false
          });
          const currentSnapshot = createHostSnapshot(latestDiscovery);
          const diff = diffHostSnapshots(previousSnapshot, currentSnapshot);

          if (!diff.changed) {
            runtime.io.stdout(
              `💓 ${timestamp()} No machine-level agent surface changes detected.\n`
            );
            previousSnapshot = currentSnapshot;
            continue;
          }

          const lines = [
            `🚨 ${timestamp()} TraceRoot Guard detected a machine-level change`
          ];

          for (const candidate of diff.newBestFirst) {
            lines.push(
              `- 🛑 New best-first surface: ${candidate.displayPath} (${candidate.categoryLabel})`,
              `  ${candidate.recommendedCommand}`
            );
          }

          for (const candidate of diff.promotedToBestFirst) {
            lines.push(
              `- ⬆️ Promoted to best-first: ${candidate.displayPath} (${candidate.categoryLabel})`,
              `  ${candidate.recommendedCommand}`
            );
          }

          for (const candidate of diff.newPossible) {
            lines.push(
              `- ➕ New possible surface: ${candidate.displayPath} (${candidate.categoryLabel})`,
              `  ${candidate.recommendedCommand}`
            );
          }

          for (const candidate of diff.removed) {
            lines.push(`- ✅ Surface disappeared: ${candidate.displayPath}`);
          }

          runtime.io.stdout(`${lines.join("\n")}\n`);
          previousSnapshot = currentSnapshot;
        }

        return;
      }

      const initialScan = await scanTarget(target);
      let previousSnapshot = createScanSnapshot(initialScan);

      runtime.io.stdout(
        [
          "TraceRoot Audit Guard",
          "=====================",
          "",
          `🎯 Target: ${target}`,
          `⏱️ Interval: every ${intervalSeconds}s`,
          `📊 Initial risk score: ${initialScan.riskScore.toFixed(1)}/10`,
          `📈 Initial findings: ${initialScan.summary.total} (${initialScan.summary.critical} critical, ${initialScan.summary.high} high, ${initialScan.summary.medium} medium)`,
          "",
          "💓 Guard is watching for:",
          "- risk score increases",
          "- new findings appearing",
          "- findings disappearing after fixes",
          ""
        ].join("\n") + "\n"
      );

      const totalCycles = maxCycles ?? Number.POSITIVE_INFINITY;

      for (let cycle = 1; cycle <= totalCycles; cycle += 1) {
        if (cycle > 1) {
          await sleep(intervalSeconds * 1000);
        }

        const latestScan = await scanTarget(target);
        const currentSnapshot = createScanSnapshot(latestScan);
        const diff = diffScanSnapshots(previousSnapshot, currentSnapshot);

        if (!diff.changed) {
          runtime.io.stdout(
            `💓 ${timestamp()} No risk changes detected. Score still ${latestScan.riskScore.toFixed(1)}/10.\n`
          );
          previousSnapshot = currentSnapshot;
          continue;
        }

        const lines = [`🚨 ${timestamp()} TraceRoot Guard detected a change`];

        if (diff.riskChanged) {
          const direction = diff.riskDelta > 0 ? "increased" : "decreased";
          const prefix = diff.riskDelta > 0 ? "📈" : "📉";
          lines.push(
            `- ${prefix} Risk score ${direction} by ${Math.abs(diff.riskDelta).toFixed(1)} to ${latestScan.riskScore.toFixed(1)}/10`
          );
        }

        if (diff.newFindingCount > 0) {
          lines.push(`- 🛑 New findings: ${diff.newFindingCount}`);
        }

        if (diff.resolvedFindingCount > 0) {
          lines.push(`- ✅ Findings resolved: ${diff.resolvedFindingCount}`);
        }

        runtime.io.stdout(`${lines.join("\n")}\n`);
        previousSnapshot = currentSnapshot;
      }
    });
}
