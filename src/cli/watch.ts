import { appendAuditEvents, resolveAuditPaths } from "../audit/store";
import type { AuditEvent, AuditSeverity } from "../audit/types";
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

function auditTimestamp(): string {
  return new Date().toISOString();
}

function watchSource(header?: string): "doctor-watch" | "guard-watch" {
  return header?.includes("Doctor") ? "doctor-watch" : "guard-watch";
}

function surfaceKindFromLabel(label: string): "runtime" | "skill" | "project" {
  if (/runtime|openclaw/i.test(label)) {
    return "runtime";
  }

  if (/skill|tool|mcp/i.test(label)) {
    return "skill";
  }

  return "project";
}

function severityFromBoundarySeverity(
  severity: BoundaryViolation["severity"]
): AuditSeverity {
  if (severity === "critical") {
    return "critical";
  }

  if (severity === "high") {
    return "high-risk";
  }

  return "risky";
}

function highestAuditSeverityForSummary(
  summary: { critical: number; high: number; medium: number }
): AuditSeverity {
  if (summary.critical > 0) {
    return "critical";
  }

  if (summary.high > 0) {
    return "high-risk";
  }

  if (summary.medium > 0) {
    return "risky";
  }

  return "safe";
}

function summarizeBoundaryViolations(status: BoundaryStatus): string {
  const preview = status.violations
    .slice(0, 3)
    .map((violation) => violation.title)
    .join("; ");

  return `Current setup is still broader than the approved boundary (${status.violations.length} issues): ${preview}.`;
}

function severityForHostCandidate(
  candidate: { tier: "best-first" | "possible"; categoryLabel: string }
): AuditSeverity {
  if (candidate.tier === "best-first" && /runtime|openclaw/i.test(candidate.categoryLabel)) {
    return "high-risk";
  }

  if (candidate.tier === "best-first") {
    return "risky";
  }

  return "safe";
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

async function writeAuditEvents(
  runtime: CliRuntime,
  events: AuditEvent[],
  state: { warned: boolean }
): Promise<void> {
  if (events.length === 0) {
    return;
  }

  try {
    await appendAuditEvents(events);
  } catch (error) {
    if (!state.warned) {
      const message =
        error instanceof Error ? error.message : "unknown audit log write error";
      runtime.io.stderr(`⚠️ Could not write local audit events: ${message}\n`);
      state.warned = true;
    }
  }
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
  const auditWriteState = { warned: false };
  const auditPaths = resolveAuditPaths();
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
    `🗂 Audit log: ${auditPaths.eventsPath}`,
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
  await writeAuditEvents(
    runtime,
    [
      {
        timestamp: auditTimestamp(),
        severity: "safe",
        category: "watch-started",
        source: "host-watch",
        target: null,
        surfaceKind: "host",
        status: "started",
        message: `Host watch started. TraceRoot is now watching common OpenClaw/runtime locations on this machine.`,
        evidence: {
          searchedRoots: initialDiscovery.searchedRoots,
          includeCwd: initialDiscovery.includeCwd
        }
      },
      {
        timestamp: auditTimestamp(),
        severity: initialBestFirst.length > 0 ? "risky" : "safe",
        category: "surface-change",
        source: "host-watch",
        target: null,
        surfaceKind: "host",
        status: "observed",
        message:
          initialDiscovery.candidates.length > 0
            ? `Host discovery currently sees ${initialDiscovery.candidates.length} likely AI action surfaces. Best first: ${initialSuggested.map((candidate) => candidate.displayPath).join(", ")}.`
            : "Host discovery is running, but no likely AI action surfaces are visible yet.",
        recommendation:
          initialSuggested[0]?.recommendedCommand ??
          "Run traceroot-audit discover --host again after your runtime or skills are installed.",
        evidence: {
          candidateCount: initialDiscovery.candidates.length,
          bestFirstCount: initialBestFirst.length
        }
      }
    ],
    auditWriteState
  );

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
    const events: AuditEvent[] = [];

    for (const candidate of diff.newBestFirst) {
      lines.push(
        `- 🛑 New best-first surface: ${candidate.displayPath} (${candidate.categoryLabel})`,
        `  ${candidate.recommendedCommand}`
      );
      events.push({
        timestamp: auditTimestamp(),
        severity: severityForHostCandidate(candidate),
        category: "surface-change",
        source: "host-watch",
        target: candidate.absolutePath,
        surfaceKind: surfaceKindFromLabel(candidate.categoryLabel),
        action: "new-best-first-surface",
        status: "changed",
        message: `A new best-first AI action surface appeared on this machine: ${candidate.displayPath} (${candidate.categoryLabel}).`,
        recommendation: candidate.recommendedCommand,
        evidence: {
          tier: candidate.tier,
          recommendedAction: candidate.recommendedAction
        }
      });
    }

    for (const candidate of diff.promotedToBestFirst) {
      lines.push(
        `- ⬆️ Promoted to best-first: ${candidate.displayPath} (${candidate.categoryLabel})`,
        `  ${candidate.recommendedCommand}`
      );
      events.push({
        timestamp: auditTimestamp(),
        severity: severityForHostCandidate(candidate),
        category: "surface-change",
        source: "host-watch",
        target: candidate.absolutePath,
        surfaceKind: surfaceKindFromLabel(candidate.categoryLabel),
        action: "promoted-best-first",
        status: "changed",
        message: `A known surface just became a best-first check: ${candidate.displayPath} (${candidate.categoryLabel}).`,
        recommendation: candidate.recommendedCommand,
        evidence: {
          tier: candidate.tier,
          recommendedAction: candidate.recommendedAction
        }
      });
    }

    for (const candidate of diff.newPossible) {
      lines.push(
        `- ➕ New possible surface: ${candidate.displayPath} (${candidate.categoryLabel})`,
        `  ${candidate.recommendedCommand}`
      );
      events.push({
        timestamp: auditTimestamp(),
        severity: "risky",
        category: "surface-change",
        source: "host-watch",
        target: candidate.absolutePath,
        surfaceKind: surfaceKindFromLabel(candidate.categoryLabel),
        action: "new-possible-surface",
        status: "changed",
        message: `A new possible AI action surface appeared: ${candidate.displayPath} (${candidate.categoryLabel}).`,
        recommendation: candidate.recommendedCommand,
        evidence: {
          tier: candidate.tier,
          recommendedAction: candidate.recommendedAction
        }
      });
    }

    for (const candidate of diff.removed) {
      lines.push(`- ✅ Surface disappeared: ${candidate.displayPath}`);
      events.push({
        timestamp: auditTimestamp(),
        severity: "safe",
        category: "surface-change",
        source: "host-watch",
        target: candidate.absolutePath,
        surfaceKind: surfaceKindFromLabel(candidate.categoryLabel),
        action: "surface-disappeared",
        status: "resolved",
        message: `A previously visible AI action surface is no longer present: ${candidate.displayPath}.`,
        evidence: {
          previousTier: candidate.tier
        }
      });
    }

    runtime.io.stdout(`${lines.join("\n")}\n`);
    await writeAuditEvents(runtime, events, auditWriteState);
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
  const source = watchSource(header);
  const auditWriteState = { warned: false };
  const auditPaths = resolveAuditPaths();
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
      `🗂 Audit log: ${auditPaths.eventsPath}`,
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
      `🗂 Audit log: ${auditPaths.eventsPath}`,
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
  const startupEvents: AuditEvent[] = [
    {
      timestamp: auditTimestamp(),
      severity: "safe",
      category: "watch-started",
      source,
      target: resolvedTarget.absolutePath,
      surfaceKind: initialScan.surface.kind,
      status: "started",
      message: `${header ?? "TraceRoot Audit Guard"} started watching this target for drift and risky changes.`,
      evidence: {
        intervalSeconds,
        currentRiskScore: initialScan.riskScore
      }
    }
  ];

  if (initialScan.summary.total > 0) {
    startupEvents.push({
      timestamp: auditTimestamp(),
      severity: highestAuditSeverityForSummary(initialScan.summary),
      category: "finding-change",
      source,
      target: resolvedTarget.absolutePath,
      surfaceKind: initialScan.surface.kind,
      status: "observed",
      message: `Live target currently starts at ${initialScan.riskScore.toFixed(1)}/10 with ${initialScan.summary.total} findings (${initialScan.summary.critical} critical, ${initialScan.summary.high} high, ${initialScan.summary.medium} medium).`,
      recommendation: `Run traceroot-audit doctor ${JSON.stringify(target)} to shrink the boundary before the next change lands.`,
      evidence: {
        riskScore: initialScan.riskScore,
        summary: initialScan.summary
      }
    });
  }

  if (previousBoundaryStatus && !previousBoundaryStatus.aligned) {
    startupEvents.push({
      timestamp: auditTimestamp(),
      severity: previousBoundaryStatus.violations.reduce<AuditSeverity>(
        (current, violation) => {
          const next = severityFromBoundarySeverity(violation.severity);
          const order: AuditSeverity[] = ["safe", "risky", "high-risk", "critical"];
          return order.indexOf(next) > order.indexOf(current) ? next : current;
        },
        "safe"
      ),
      category: "boundary-drift",
      source,
      target: resolvedTarget.absolutePath,
      surfaceKind: initialScan.surface.kind,
      status: "observed",
      message: summarizeBoundaryViolations(previousBoundaryStatus),
      recommendation: previousBoundaryStatus.violations[0]?.recommendation,
      evidence: {
        violations: previousBoundaryStatus.violations.map((violation) => violation.title)
      }
    });
  }

  await writeAuditEvents(runtime, startupEvents, auditWriteState);

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
    const events: AuditEvent[] = [];

    if (diff.riskChanged) {
      const direction = diff.riskDelta > 0 ? "increased" : "decreased";
      const prefix = diff.riskDelta > 0 ? "📈" : "📉";
      lines.push(
        `- ${prefix} Risk score ${direction} by ${Math.abs(diff.riskDelta).toFixed(1)} to ${latestScan.riskScore.toFixed(1)}/10`
      );
      events.push({
        timestamp: auditTimestamp(),
        severity:
          diff.riskDelta > 0
            ? highestAuditSeverityForSummary(latestScan.summary)
            : "safe",
        category: "risk-change",
        source,
        target: resolvedTarget.absolutePath,
        surfaceKind: latestScan.surface.kind,
        status: "changed",
        message: `Risk score ${direction} by ${Math.abs(diff.riskDelta).toFixed(1)} to ${latestScan.riskScore.toFixed(1)}/10.`,
        evidence: {
          riskDelta: diff.riskDelta,
          riskScore: latestScan.riskScore
        }
      });
    }

    if (diff.newFindingCount > 0) {
      lines.push(`- 🛑 New findings: ${diff.newFindingCount}`);
      events.push({
        timestamp: auditTimestamp(),
        severity: highestAuditSeverityForSummary(latestScan.summary),
        category: "finding-change",
        source,
        target: resolvedTarget.absolutePath,
        surfaceKind: latestScan.surface.kind,
        action: "new-findings",
        status: "changed",
        message: `${diff.newFindingCount} new findings appeared while this target was under watch.`,
        recommendation:
          latestScan.findings[0]?.recommendation ??
          "Run traceroot-audit doctor to shrink the boundary again.",
        evidence: {
          newFindingCount: diff.newFindingCount,
          totalFindings: latestScan.summary.total
        }
      });
    }

    if (diff.resolvedFindingCount > 0) {
      lines.push(`- ✅ Findings resolved: ${diff.resolvedFindingCount}`);
      events.push({
        timestamp: auditTimestamp(),
        severity: "safe",
        category: "finding-change",
        source,
        target: resolvedTarget.absolutePath,
        surfaceKind: latestScan.surface.kind,
        action: "resolved-findings",
        status: "resolved",
        message: `${diff.resolvedFindingCount} findings were resolved while this target was under watch.`,
        evidence: {
          resolvedFindingCount: diff.resolvedFindingCount,
          totalFindings: latestScan.summary.total
        }
      });
    }

    if (boundaryDiff) {
      for (const violation of boundaryDiff.newViolations) {
        lines.push(renderViolationLine(violation));
        events.push({
          timestamp: auditTimestamp(),
          severity: severityFromBoundarySeverity(violation.severity),
          category: "boundary-drift",
          source,
          target: resolvedTarget.absolutePath,
          surfaceKind: latestScan.surface.kind,
          action: violation.code,
          status: "changed",
          message: violation.message,
          recommendation: violation.recommendation,
          evidence: {
            title: violation.title
          }
        });
      }

      for (const violation of boundaryDiff.resolvedViolations) {
        lines.push(`- ✅ Boundary restored: ${violation.title}`);
        events.push({
          timestamp: auditTimestamp(),
          severity: "safe",
          category: "boundary-drift",
          source,
          target: resolvedTarget.absolutePath,
          surfaceKind: latestScan.surface.kind,
          action: violation.code,
          status: "resolved",
          message: `Boundary restored for: ${violation.title}.`,
          evidence: {
            title: violation.title
          }
        });
      }
    }

    runtime.io.stdout(`${lines.join("\n")}\n`);
    await writeAuditEvents(runtime, events, auditWriteState);
    previousSnapshot = currentSnapshot;
    if (currentBoundaryStatus) {
      previousBoundaryStatus = currentBoundaryStatus;
    }
  }
}
