import { discoverHost } from "../core/discovery";
import {
  createHostSnapshot,
  createScanSnapshot,
  diffHostSnapshots,
  diffScanSnapshots
} from "../core/guard";
import { scanTarget } from "../core/scanner";
import { buildCurrentHardeningState } from "../hardening/analysis";
import {
  diffBoundaryStatus,
  evaluateBoundaryStatus,
  type BoundaryStatus,
  type BoundaryViolation
} from "../hardening/boundary";
import { loadHardeningProfile } from "../hardening/profile";
import {
  getHardeningProfileById,
  type HardeningIntentId
} from "../hardening/profiles";
import { resolveTarget } from "../utils/files";

import type { CliRuntime } from "./index";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function timestamp(): string {
  return new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function renderWorkflowSummary(profilePath: string, selectedIntentIds: string[]): string[] {
  const workflows = selectedIntentIds
    .map((intentId) => {
      try {
        const profile = getHardeningProfileById(intentId as HardeningIntentId);
        return `${profile.icon} ${profile.title}`;
      } catch {
        return intentId;
      }
    })
    .join(", ");

  return [
    `🛡️ Approved boundary: ${profilePath}`,
    `🧩 Approved workflows: ${workflows || "none recorded"}`
  ];
}

function renderBoundaryStatus(status: BoundaryStatus): string[] {
  if (status.aligned) {
    return [
      "✅ Current setup matches the approved boundary.",
      "💓 Guard will watch for any future drift beyond it."
    ];
  }

  const lines = ["🚧 Current setup is still broader than the approved boundary."];

  for (const violation of status.violations.slice(0, 4)) {
    const icon =
      violation.severity === "critical"
        ? "🛑"
        : violation.severity === "high"
          ? "⚠️"
          : "ℹ️";
    lines.push(`- ${icon} ${violation.title}: ${violation.message}`);
  }

  const recommendations = [
    ...new Set(status.violations.map((violation) => violation.recommendation))
  ];
  if (recommendations.length > 0) {
    lines.push("", "🔧 Best next fixes:");

    for (const recommendation of recommendations.slice(0, 3)) {
      lines.push(`- ${recommendation}`);
    }
  }

  return lines;
}

function renderViolationLine(violation: BoundaryViolation): string {
  const icon =
    violation.severity === "critical"
      ? "🛑"
      : violation.severity === "high"
        ? "⚠️"
        : "ℹ️";

  return `- ${icon} ${violation.title}: ${violation.message}`;
}

export async function runHostWatch(options: {
  runtime: CliRuntime;
  intervalSeconds: number;
  maxCycles?: number;
  includeCwd?: boolean;
  header?: string;
}): Promise<void> {
  const { runtime, intervalSeconds, maxCycles, includeCwd, header } = options;
  const initialDiscovery = await discoverHost({
    includeCwd: includeCwd ?? false
  });
  let previousSnapshot = createHostSnapshot(initialDiscovery);
  const initialBestFirst = initialDiscovery.candidates.filter(
    (candidate) => candidate.tier === "best-first"
  );
  const initialSuggested = (
    initialBestFirst.length > 0 ? initialBestFirst : initialDiscovery.candidates
  ).slice(0, 3);

  const initialLines = [
    header ?? "TraceRoot Audit Guard",
    "=".repeat((header ?? "TraceRoot Audit Guard").length),
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
      includeCwd: includeCwd ?? false
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
}

export async function runTargetWatch(options: {
  runtime: CliRuntime;
  target: string;
  intervalSeconds: number;
  maxCycles?: number;
  header?: string;
  compactStart?: boolean;
}): Promise<void> {
  const { runtime, target, intervalSeconds, maxCycles, header, compactStart } = options;
  const resolvedTarget = await resolveTarget(target);
  const initialScan = await scanTarget(target);
  let previousSnapshot = createScanSnapshot(initialScan);
  const hardeningProfileResult = await loadHardeningProfile(resolvedTarget.rootDir);
  let previousBoundaryStatus: BoundaryStatus | null = null;

  if (hardeningProfileResult.profile) {
    const initialBoundaryState = await buildCurrentHardeningState(
      target,
      hardeningProfileResult.profile.selectedIntents.map(
        (intent) => intent.id as HardeningIntentId
      )
    );
    previousBoundaryStatus = evaluateBoundaryStatus(
      hardeningProfileResult.profile,
      initialBoundaryState
    );
  }

  const title = header ?? "TraceRoot Audit Guard";
  const initialLines = [title, "=".repeat(title.length), ""];

  if (compactStart) {
    initialLines.push(
      `🎯 Watching target: ${target}`,
      `⏱️ Interval: every ${intervalSeconds}s`,
      `📊 Current score: ${initialScan.riskScore.toFixed(1)}/10`,
      `📈 Current findings: ${initialScan.summary.total}`,
      ""
    );

    if (hardeningProfileResult.profilePath) {
      initialLines.push(
        hardeningProfileResult.profile
          ? `🛡️ Approved boundary loaded: ${hardeningProfileResult.profilePath}`
          : `⚠️ Saved boundary could not be loaded cleanly: ${hardeningProfileResult.error ?? "unknown error"}`
      );
    }

    initialLines.push(
      "💓 Doctor Watch is now keeping an eye on:",
      "- risk score increases",
      "- new findings appearing",
      "- boundary drift beyond what you approved",
      ""
    );
  } else {
    initialLines.push(
      `🎯 Target: ${target}`,
      `⏱️ Interval: every ${intervalSeconds}s`,
      `📊 Initial risk score: ${initialScan.riskScore.toFixed(1)}/10`,
      `📈 Initial findings: ${initialScan.summary.total} (${initialScan.summary.critical} critical, ${initialScan.summary.high} high, ${initialScan.summary.medium} medium)`
    );

    if (hardeningProfileResult.profilePath) {
      initialLines.push(
        "",
        ...(hardeningProfileResult.profile
          ? renderWorkflowSummary(
              hardeningProfileResult.profilePath,
              hardeningProfileResult.profile.selectedIntents.map((intent) => intent.id)
            )
          : [
              `🛡️ Approved boundary: ${hardeningProfileResult.profilePath}`,
              `⚠️ Saved boundary could not be loaded cleanly: ${hardeningProfileResult.error ?? "unknown error"}`
            ])
      );

      if (hardeningProfileResult.profile && previousBoundaryStatus) {
        initialLines.push("", ...renderBoundaryStatus(previousBoundaryStatus));
      }
    }

    initialLines.push(
      "",
      "💓 Guard is watching for:",
      "- risk score increases",
      "- new findings appearing",
      "- findings disappearing after fixes"
    );

    if (hardeningProfileResult.profile) {
      initialLines.push("- power drifting beyond your approved boundary");
    }

    initialLines.push("");
  }

  runtime.io.stdout(`${initialLines.join("\n")}\n`);

  const totalCycles = maxCycles ?? Number.POSITIVE_INFINITY;

  for (let cycle = 1; cycle <= totalCycles; cycle += 1) {
    if (cycle > 1) {
      await sleep(intervalSeconds * 1000);
    }

    const latestScan = await scanTarget(target);
    const currentSnapshot = createScanSnapshot(latestScan);
    const diff = diffScanSnapshots(previousSnapshot, currentSnapshot);
    let boundaryDiff = null;
    let currentBoundaryStatus: BoundaryStatus | null = null;

    if (hardeningProfileResult.profile && previousBoundaryStatus) {
      const latestBoundaryState = await buildCurrentHardeningState(
        target,
        hardeningProfileResult.profile.selectedIntents.map(
          (intent) => intent.id as HardeningIntentId
        )
      );
      currentBoundaryStatus = evaluateBoundaryStatus(
        hardeningProfileResult.profile,
        latestBoundaryState
      );
      boundaryDiff = diffBoundaryStatus(previousBoundaryStatus, currentBoundaryStatus);
    }

    if (!diff.changed && !boundaryDiff?.changed) {
      const heartbeat =
        currentBoundaryStatus?.aligned === false
          ? `💓 ${timestamp()} No new risk or boundary changes. Current setup is still broader than the approved boundary (${currentBoundaryStatus.violations.length} issues). Score still ${latestScan.riskScore.toFixed(1)}/10.\n`
          : `💓 ${timestamp()} No risk or boundary changes detected. Score still ${latestScan.riskScore.toFixed(1)}/10.\n`;

      runtime.io.stdout(heartbeat);
      previousSnapshot = currentSnapshot;
      if (currentBoundaryStatus) {
        previousBoundaryStatus = currentBoundaryStatus;
      }
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

    if (boundaryDiff) {
      for (const violation of boundaryDiff.newViolations) {
        lines.push(renderViolationLine(violation));
      }

      for (const violation of boundaryDiff.resolvedViolations) {
        lines.push(`- ✅ Boundary restored: ${violation.title}`);
      }
    }

    runtime.io.stdout(`${lines.join("\n")}\n`);
    previousSnapshot = currentSnapshot;
    if (currentBoundaryStatus) {
      previousBoundaryStatus = currentBoundaryStatus;
    }
  }
}
