import { appendAuditEvents, readAuditEvents, resolveAuditPaths } from "../audit/store";
import type { AuditEvent, AuditSeverity } from "../audit/types";
import { actionLabel } from "../audit/presentation";
import {
  hasNotificationChannel,
  resolveNotificationConfig,
  sendOpenClawChannelNotification,
  sendWebhookNotification,
  validateNotificationConfig,
  type NotificationConfig,
  type ResolvedNotificationConfig
} from "../audit/notifier";
import {
  createRuntimeFeedCursor,
  discoverRuntimeEventFeeds,
  readNewRuntimeFeedEvents
} from "../audit/feeds";
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
import { displayUserPath } from "../utils/paths";

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

function actionEventKey(event: AuditEvent): string {
  return [
    event.timestamp,
    event.category,
    event.status ?? "",
    event.action ?? "",
    event.target ?? "",
    event.message
  ].join("::");
}

function actionAlertFingerprint(event: AuditEvent): string {
  return [
    event.action ?? "",
    event.runtime ?? "",
    event.target ?? "",
    event.severity
  ].join("::");
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

  return `当前配置仍然比你批准的边界更宽（${status.violations.length} 个点）：${preview}。`;
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
    `🛡️ 已批准边界：${profilePath}`,
    `🧩 已批准工作流：${workflows || "暂时没有记录"}`
  ];
}

function renderBoundaryStatus(status: BoundaryStatus): string[] {
  if (status.aligned) {
    return [
      "✅ 当前配置已经和你批准的边界对齐了。",
      "💓 TraceRoot 会继续盯着，后面只要再变宽就会提醒你。"
    ];
  }

  const lines = ["🚧 当前配置仍然比你批准的边界更宽。"];

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
    lines.push("", "🔧 最值得先修的地方：");

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

function alertIconForSeverity(severity: AuditSeverity): string {
  if (severity === "critical") {
    return "🚨";
  }

  if (severity === "high-risk") {
    return "🛑";
  }

  if (severity === "risky") {
    return "⚠️";
  }

  return "🟢";
}

function heartbeatIntervalMs(options: {
  header?: string;
  intervalSeconds: number;
}): number {
  if (options.header?.includes("Doctor")) {
    return Math.max(options.intervalSeconds * 1000 * 10, 300_000);
  }

  return Math.max(options.intervalSeconds * 1000 * 5, 60_000);
}

function shouldEmitHeartbeat(options: {
  now: number;
  cycle: number;
  totalCycles: number;
  lastHeartbeatAt: number;
  heartbeatEveryMs: number;
}): boolean {
  if (options.cycle === 1) {
    return true;
  }

  if (Number.isFinite(options.totalCycles) && options.cycle === options.totalCycles) {
    return true;
  }

  return options.now - options.lastHeartbeatAt >= options.heartbeatEveryMs;
}

function renderLiveActionAlert(event: AuditEvent): string[] {
  const icon = alertIconForSeverity(event.severity);
  const lines = [
    `${icon} ${timestamp()} TraceRoot 实时提醒`,
    `- Agent 刚刚触发了一个${event.severity === "critical" ? "极高风险" : event.severity === "high-risk" ? "高风险" : "有风险"}动作：${actionLabel(event.action)}`
  ];

  if (event.target) {
    lines.push(`- 位置：${displayUserPath(event.target)}`);
  }

  if (event.status === "attempted") {
    lines.push("- 状态：正在尝试执行");
  } else if (event.status === "failed") {
    lines.push("- 状态：执行失败，但这次尝试已经被记进审计时间线");
  } else if (event.status === "succeeded") {
    lines.push("- 状态：已经执行成功，并已记进审计时间线");
  }

  if (event.recommendation) {
    lines.push(`- 建议：${event.recommendation}`);
  }

  lines.push("- 想查看完整来龙去脉，可以运行：traceroot-audit logs");
  return lines;
}

function isAlertWorthyActionEvent(event: AuditEvent): boolean {
  return (
    event.category === "action-event" &&
    event.severity !== "safe" &&
    (event.status === "attempted" ||
      event.status === "failed")
  );
}

function happenedRecently(timestampValue: string, windowMs: number): boolean {
  const value = new Date(timestampValue).getTime();
  if (Number.isNaN(value)) {
    return false;
  }

  return Date.now() - value <= windowMs;
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

async function notifyActionEvent(
  runtime: CliRuntime,
  event: AuditEvent,
  notificationConfig: ResolvedNotificationConfig,
  state: { warned: boolean }
): Promise<void> {
  if (!hasNotificationChannel(notificationConfig)) {
    return;
  }

  try {
    await Promise.all([
      sendWebhookNotification(event, notificationConfig),
      sendOpenClawChannelNotification(event, notificationConfig)
    ]);
  } catch (error) {
    if (!state.warned) {
      const message =
        error instanceof Error ? error.message : "unknown notification delivery error";
      runtime.io.stderr(
        `⚠️ TraceRoot 没能把这次提醒同步发出去，不过本地审计记录还在继续。\n   原因：${message}\n`
      );
      state.warned = true;
    }
  }
}

async function emitLiveActionAlerts(options: {
  runtime: CliRuntime;
  events: AuditEvent[];
  seenActionEvents: Set<string>;
  notificationConfig: ResolvedNotificationConfig;
  notificationState: { warned: boolean };
  alertState: { lastSentAtByFingerprint: Map<string, number> };
}): Promise<void> {
  const {
    runtime,
    events,
    seenActionEvents,
    notificationConfig,
    notificationState,
    alertState
  } = options;

  const now = Date.now();

  for (const event of events) {
    const fingerprint = actionAlertFingerprint(event);
    const previousSentAt = alertState.lastSentAtByFingerprint.get(fingerprint) ?? 0;

    if (now - previousSentAt < notificationConfig.cooldownMs) {
      seenActionEvents.add(actionEventKey(event));
      continue;
    }

    runtime.io.stdout(`${renderLiveActionAlert(event).join("\n")}\n`);
    await notifyActionEvent(runtime, event, notificationConfig, notificationState);
    alertState.lastSentAtByFingerprint.set(fingerprint, now);
    seenActionEvents.add(actionEventKey(event));
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
  notifications?: NotificationConfig;
}): Promise<void> {
  const { runtime, target, intervalSeconds, maxCycles, header, compactStart } = options;
  const resolvedTarget = await resolveTarget(target);
  const source = watchSource(header);
  const auditWriteState = { warned: false };
  const notificationState = { warned: false };
  const notificationConfig = resolveNotificationConfig(options.notifications);
  const notificationValidationError = validateNotificationConfig(notificationConfig);

  if (notificationValidationError) {
    runtime.io.stderr(`${notificationValidationError}\n`);
    runtime.exitCode = 1;
    return;
  }
  const alertState = {
    lastSentAtByFingerprint: new Map<string, number>()
  };
  const heartbeatEveryMs = heartbeatIntervalMs({
    header,
    intervalSeconds
  });
  let lastHeartbeatAt = 0;
  const auditPaths = resolveAuditPaths();
  const initialScan = await scanTarget(target);
  let previousSnapshot = createScanSnapshot(initialScan);
  let lastDeepCheckAt = Date.now();
  const deepCheckIntervalMs = Math.max(intervalSeconds * 1000, 30_000);
  const initialAuditEvents = await readAuditEvents({
    target: resolvedTarget.absolutePath
  });
  const seenActionEvents = new Set(
    initialAuditEvents.events
      .filter((event) => event.category === "action-event")
      .map(actionEventKey)
  );
  const recentStartupAlerts = initialAuditEvents.events
    .filter(isAlertWorthyActionEvent)
    .filter((event) => happenedRecently(event.timestamp, Math.max(intervalSeconds * 2000, 30_000)))
    .slice(0, 3);
  const hardeningProfileResult = await loadHardeningProfile(resolvedTarget.rootDir);
  const runtimeFeeds = await discoverRuntimeEventFeeds(resolvedTarget.rootDir);
  const runtimeFeedCursor = await createRuntimeFeedCursor(runtimeFeeds);
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
      `🎯 正在陪跑: ${target}`,
      `⏱️ 检查间隔: 每 ${intervalSeconds}s`,
      `🗂 审计日志: ${auditPaths.eventsPath}`,
      `📊 当前风险分: ${initialScan.riskScore.toFixed(1)}/10`,
      `📈 当前发现: ${initialScan.summary.total}`,
      ""
    );

    if (hardeningProfileResult.profilePath) {
      initialLines.push(
        hardeningProfileResult.profile
          ? `🛡️ 已加载批准边界：${hardeningProfileResult.profilePath}`
          : `⚠️ 之前保存的边界没能顺利读出来：${hardeningProfileResult.error ?? "unknown error"}`
      );
    }

    initialLines.push(
      "💓 Doctor Watch 现在会继续盯着：",
      "- 风险分突然升高",
      "- 新风险突然出现",
      "- 当前配置又比你批准的边界更宽",
      "- 高风险动作会尽快提醒你，但相同动作短时间内不会反复打扰",
      "- 如果暂时没什么值得你注意的动作，TraceRoot 会安静地继续陪跑，不会反复刷屏",
      ""
    );
  } else {
    initialLines.push(
      `🎯 Target: ${target}`,
      `⏱️ Interval: every ${intervalSeconds}s`,
      `🗂 审计日志: ${auditPaths.eventsPath}`,
      `📊 初始风险分：${initialScan.riskScore.toFixed(1)}/10`,
      `📈 初始发现：${initialScan.summary.total}（critical ${initialScan.summary.critical} / high ${initialScan.summary.high} / medium ${initialScan.summary.medium}）`
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
              `🛡️ 已批准边界：${hardeningProfileResult.profilePath}`,
              `⚠️ 之前保存的边界没能顺利读出来：${hardeningProfileResult.error ?? "unknown error"}`
            ])
      );

      if (hardeningProfileResult.profile && previousBoundaryStatus) {
        initialLines.push("", ...renderBoundaryStatus(previousBoundaryStatus));
      }
    }

    initialLines.push(
      "",
      "💓 TraceRoot Guard 现在会继续盯着：",
      "- 风险分突然升高",
      "- 新风险突然出现",
      "- 修复后哪些风险消失了"
    );

    if (hardeningProfileResult.profile) {
      initialLines.push("- 当前配置有没有重新超出你批准的边界");
    }

    initialLines.push("- 高风险动作会尽快提醒你，但相同动作短时间内不会反复打扰");
    initialLines.push("- 如果暂时没什么值得你注意的动作，TraceRoot 会安静地继续陪跑，不会反复刷屏");

    initialLines.push("");
  }

  if (notificationConfig.openclawChannel && notificationConfig.openclawTarget) {
    initialLines.push(
      `📣 高风险动作一出现，TraceRoot 也会同步把提醒发到你选好的聊天入口：${notificationConfig.openclawChannel} → ${notificationConfig.openclawTarget}`,
      ""
    );
  } else if (hasNotificationChannel(notificationConfig)) {
    initialLines.push(
      "📣 高风险动作一出现，TraceRoot 也会同步把提醒发到你接好的通知入口。",
      ""
    );
  }

  if (runtimeFeeds.length > 0) {
    initialLines.push(
      "🔌 TraceRoot 还会继续听这些运行时事件入口：",
      ...runtimeFeeds.slice(0, 3).map((feed) => `- ${feed.displayPath}`)
    );

    if (runtimeFeeds.length > 3) {
      initialLines.push(`- 还有 ${runtimeFeeds.length - 3} 个入口也会一起监听`);
    }

    initialLines.push("");
  }

  runtime.io.stdout(`${initialLines.join("\n")}\n`);

  if (recentStartupAlerts.length > 0) {
    await emitLiveActionAlerts({
      runtime,
      events: recentStartupAlerts.reverse(),
      seenActionEvents,
      notificationConfig: {},
      notificationState,
      alertState
    });
  }

  const startupEvents: AuditEvent[] = [
    {
      timestamp: auditTimestamp(),
        severity: "safe",
        category: "watch-started",
        source,
        target: resolvedTarget.absolutePath,
        surfaceKind: initialScan.surface.kind,
        status: "started",
        message: `TraceRoot 已经开始陪跑这个 target，会继续盯着边界变化和高风险动作。`,
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
        message: `当前这套 live 配置一开始就在 ${initialScan.riskScore.toFixed(1)}/10，并且有 ${initialScan.summary.total} 条风险发现（critical ${initialScan.summary.critical} / high ${initialScan.summary.high} / medium ${initialScan.summary.medium}）。`,
        recommendation: `先运行 traceroot-audit doctor ${JSON.stringify(target)}，把边界收紧后再继续陪跑。`,
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

    const latestRuntimeFeeds = await discoverRuntimeEventFeeds(resolvedTarget.rootDir);
    for (const feed of latestRuntimeFeeds) {
      if (!runtimeFeeds.some((existing) => existing.absolutePath === feed.absolutePath)) {
        runtimeFeeds.push(feed);
        runtimeFeedCursor.lineCounts.set(feed.absolutePath, 0);
      }
    }

    const feedEvents = await readNewRuntimeFeedEvents({
      feeds: runtimeFeeds,
      cursor: runtimeFeedCursor,
      targetRoot: resolvedTarget.rootDir
    });
    await writeAuditEvents(runtime, feedEvents, auditWriteState);
    const now = Date.now();
    const shouldRunDeepCheck =
      cycle === 1 || now - lastDeepCheckAt >= deepCheckIntervalMs;
    let latestScan = initialScan;
    let currentSnapshot = previousSnapshot;
    let diff = {
      changed: false,
      riskChanged: false,
      riskDelta: 0,
      newFindingCount: 0,
      resolvedFindingCount: 0
    };
    let boundaryDiff = null;
    let currentBoundaryStatus: BoundaryStatus | null = null;

    if (shouldRunDeepCheck) {
      latestScan = await scanTarget(target);
      currentSnapshot = createScanSnapshot(latestScan);
      diff = diffScanSnapshots(previousSnapshot, currentSnapshot);
      lastDeepCheckAt = now;

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
      } else {
        currentBoundaryStatus = previousBoundaryStatus;
      }
    } else {
      currentBoundaryStatus = previousBoundaryStatus;
    }

    if (!diff.changed && !boundaryDiff?.changed) {
      const latestAuditEvents = await readAuditEvents({
        target: resolvedTarget.absolutePath
      });
      const newActionAlerts = latestAuditEvents.events
        .filter(isAlertWorthyActionEvent)
        .filter((event) => !seenActionEvents.has(actionEventKey(event)))
        ;
      await emitLiveActionAlerts({
        runtime,
        events: newActionAlerts,
        seenActionEvents,
        notificationConfig,
        notificationState,
        alertState
      });

      for (const event of latestAuditEvents.events) {
        if (event.category === "action-event") {
          seenActionEvents.add(actionEventKey(event));
        }
      }

      if (newActionAlerts.length > 0) {
        if (shouldRunDeepCheck) {
          previousSnapshot = currentSnapshot;
        }
        if (currentBoundaryStatus && shouldRunDeepCheck) {
          previousBoundaryStatus = currentBoundaryStatus;
        }
        continue;
      }

      if (!shouldRunDeepCheck) {
        continue;
      }

      if (
        shouldEmitHeartbeat({
          now,
          cycle,
          totalCycles,
          lastHeartbeatAt,
          heartbeatEveryMs
        })
      ) {
        const heartbeat =
          currentBoundaryStatus?.aligned === false
            ? `💓 ${timestamp()} 这轮没有新的风险变化，不过当前配置仍然比你批准的边界更宽（${currentBoundaryStatus.violations.length} 个点）。风险分仍然是 ${latestScan.riskScore.toFixed(1)}/10。\n`
            : `💓 ${timestamp()} 这轮没有发现新的风险或边界变化。风险分仍然是 ${latestScan.riskScore.toFixed(1)}/10。\n`;

        runtime.io.stdout(heartbeat);
        lastHeartbeatAt = now;
      }
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

    const latestAuditEvents = await readAuditEvents({
      target: resolvedTarget.absolutePath
    });
    const newActionAlerts = latestAuditEvents.events
      .filter(isAlertWorthyActionEvent)
      .filter((event) => !seenActionEvents.has(actionEventKey(event)))
      ;
    await emitLiveActionAlerts({
      runtime,
      events: newActionAlerts,
      seenActionEvents,
      notificationConfig,
      notificationState,
      alertState
    });

    for (const event of latestAuditEvents.events) {
      if (event.category === "action-event") {
        seenActionEvents.add(actionEventKey(event));
      }
    }

    previousSnapshot = currentSnapshot;
    if (currentBoundaryStatus) {
      previousBoundaryStatus = currentBoundaryStatus;
    }
  }
}
