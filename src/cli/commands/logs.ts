import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { Command, Option } from "commander";

import { readAuditEvents } from "../../audit/store";
import type { AuditEvent, AuditSeverity } from "../../audit/types";
import { actionLabel } from "../../audit/presentation";
import {
  loadRecentDoctorContext,
  recentTargetLabel
} from "../../hardening/recent-target";
import { displayUserPath } from "../../utils/paths";

import type { CliRuntime } from "../index";

interface LogsOptions {
  target?: string;
  severity?: AuditSeverity;
  today?: boolean;
  limit: string;
  tail?: boolean;
  interval: string;
  all?: boolean;
}

type TimelineEntry = {
  primary: AuditEvent;
  related: AuditEvent[];
};

function severityIcon(severity: AuditSeverity): string {
  switch (severity) {
    case "critical":
      return "🚨";
    case "high-risk":
      return "🛑";
    case "risky":
      return "⚠️";
    case "safe":
    default:
      return "🟢";
  }
}

function formatTimestamp(value: string): string {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("en-GB", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function categoryLabel(event: AuditEvent): string {
  switch (event.category) {
    case "watch-started":
      return "开始陪跑";
    case "watch-heartbeat":
      return "陪跑心跳";
    case "risk-change":
      return "风险变化";
    case "finding-change":
      return "发现变化";
    case "boundary-drift":
      return "边界漂移";
    case "surface-change":
      return "入口变化";
    case "action-event":
      return "Agent 动作";
    default:
      return event.category;
  }
}

function actorLabel(event: AuditEvent): string {
  const runtime = event.runtime?.trim();

  if (runtime) {
    const normalized = runtime.toLowerCase();

    if (normalized === "openclaw") {
      return "OpenClaw 运行时";
    }

    if (normalized === "mcp") {
      return "MCP 服务";
    }

    return runtime;
  }

  if (event.target) {
    return path.basename(event.target);
  }

  return "这个 agent";
}

function eventHeadline(event: AuditEvent): string {
  if (event.category === "action-event") {
    const label = actionLabel(event.action);

    switch (event.status) {
      case "attempted":
        return `Agent 开始尝试：${label}`;
      case "succeeded":
        return `Agent 已完成：${label}`;
      case "failed":
        return `Agent 没有完成：${label}`;
      default:
        return `Agent 触发了一个动作：${label}`;
    }
  }

  switch (event.category) {
    case "watch-started":
      return "TraceRoot 已经开始陪跑这个 agent";
    case "watch-heartbeat":
      return "TraceRoot 还在继续陪跑";
    case "risk-change":
      return "整体风险出现了变化";
    case "finding-change":
      return "TraceRoot 发现了新的风险信号";
    case "boundary-drift":
      return "当前运行态重新变宽了";
    case "surface-change":
      return "机器上的 agent 入口有变化";
    default:
      return categoryLabel(event);
  }
}

function eventTimeMs(event: AuditEvent): number {
  const value = new Date(event.timestamp).getTime();
  return Number.isNaN(value) ? 0 : value;
}

function canFoldIntoOneIncident(first: AuditEvent, next: AuditEvent): boolean {
  if (first.category !== "action-event" || next.category !== "action-event") {
    return false;
  }

  if (first.status !== "attempted") {
    return false;
  }

  if (!(next.status === "succeeded" || next.status === "failed")) {
    return false;
  }

  if (
    first.action !== next.action ||
    first.runtime !== next.runtime ||
    first.target !== next.target
  ) {
    return false;
  }

  return Math.abs(eventTimeMs(next) - eventTimeMs(first)) <= 2 * 60 * 1000;
}

function buildTimelineEntries(eventsAscending: AuditEvent[]): TimelineEntry[] {
  const entries: TimelineEntry[] = [];

  for (let index = 0; index < eventsAscending.length; index += 1) {
    const current = eventsAscending[index]!;
    const next = eventsAscending[index + 1];

    if (next && canFoldIntoOneIncident(current, next)) {
      entries.push({
        primary: next,
        related: [current]
      });
      index += 1;
      continue;
    }

    entries.push({
      primary: current,
      related: []
    });
  }

  return entries;
}

function looksLikeGenericRuntimeNarration(message: string): boolean {
  const normalized = message.trim();
  return [
    /^agent is attempting to /i,
    /^agent attempted to /i,
    /^agent started to /i,
    /^agent completed /i,
    /^agent finished /i,
    /^agent succeeded /i,
    /^agent failed /i,
    /^agent triggered /i
  ].some((pattern) => pattern.test(normalized));
}

function eventDetail(event: AuditEvent): string | undefined {
  if (!event.message) {
    return undefined;
  }

  if (event.category !== "action-event") {
    return event.message;
  }

  if (!looksLikeGenericRuntimeNarration(event.message)) {
    return event.message;
  }

  switch (event.status) {
    case "attempted":
      return "这个动作刚刚开始，TraceRoot 已经先把它记进审计时间线里。";
    case "succeeded":
      return "这个动作已经执行完成，TraceRoot 也已经把它记下来了。";
    case "failed":
      return "这次动作没有完成，不过 TraceRoot 已经把整个尝试过程记下来了。";
    default:
      return "TraceRoot 已经把这次动作记进审计时间线里。";
  }
}

function timelineHeadline(entry: TimelineEntry): string {
  if (entry.related.length === 0) {
    return eventHeadline(entry.primary);
  }

  const actor = actorLabel(entry.primary);
  const label = actionLabel(entry.primary.action);

  if (entry.primary.status === "succeeded") {
    return `${actor} 已完成：${label}`;
  }

  if (entry.primary.status === "failed") {
    return `${actor} 没有完成：${label}`;
  }

  return eventHeadline(entry.primary);
}

function timelineDetail(entry: TimelineEntry): string | undefined {
  if (entry.related.length === 0) {
    return eventDetail(entry.primary);
  }

  if (entry.primary.status === "succeeded") {
    return "TraceRoot 看到这个动作先被触发，随后已经执行完成。";
  }

  if (entry.primary.status === "failed") {
    return "TraceRoot 看到这个动作先被触发，不过最后没有完成。";
  }

  return eventDetail(entry.primary);
}

function summarizeEvents(events: AuditEvent[]): {
  critical: number;
  highRisk: number;
  risky: number;
  safe: number;
  actionEvents: number;
  boundaryEvents: number;
  driftEvents: number;
  latestAttention: AuditEvent | null;
  attentionActions: Array<{
    actionLabel: string;
    count: number;
    failed: number;
    severity: AuditSeverity;
  }>;
  attentionActors: Array<{
    actorLabel: string;
    count: number;
    severity: AuditSeverity;
    actions: string[];
  }>;
} {
  let critical = 0;
  let highRisk = 0;
  let risky = 0;
  let safe = 0;
  let actionEvents = 0;
  let boundaryEvents = 0;
  let driftEvents = 0;
  let latestAttention: AuditEvent | null = null;
  const attentionActions = new Map<
    string,
    { actionLabel: string; count: number; failed: number; severity: AuditSeverity }
  >();
  const attentionActors = new Map<
    string,
    { actorLabel: string; count: number; severity: AuditSeverity; actions: Set<string> }
  >();

  const severityWeight = (severity: AuditSeverity): number => {
    if (severity === "critical") return 4;
    if (severity === "high-risk") return 3;
    if (severity === "risky") return 2;
    return 1;
  };

  for (const event of events) {
    if (event.severity === "critical") critical += 1;
    else if (event.severity === "high-risk") highRisk += 1;
    else if (event.severity === "risky") risky += 1;
    else safe += 1;

    if (event.category === "action-event") {
      actionEvents += 1;

      if (event.severity !== "safe") {
        const label = actionLabel(event.action);
        const existing = attentionActions.get(label) ?? {
          actionLabel: label,
          count: 0,
          failed: 0,
          severity: event.severity
        };

        existing.count += 1;
        if (event.status === "failed") {
          existing.failed += 1;
        }
        if (event.severity === "critical") {
          existing.severity = "critical";
        } else if (event.severity === "high-risk" && existing.severity !== "critical") {
          existing.severity = "high-risk";
        } else if (event.severity === "risky" && existing.severity === "safe") {
          existing.severity = "risky";
        }

        attentionActions.set(label, existing);

        const actor = actorLabel(event);
        const actorEntry = attentionActors.get(actor) ?? {
          actorLabel: actor,
          count: 0,
          severity: event.severity,
          actions: new Set<string>()
        };

        actorEntry.count += 1;
        actorEntry.actions.add(label);
        if (severityWeight(event.severity) > severityWeight(actorEntry.severity)) {
          actorEntry.severity = event.severity;
        }

        attentionActors.set(actor, actorEntry);
      }
    }

    if (event.category === "boundary-drift") {
      boundaryEvents += 1;
      driftEvents += 1;
    }

    if (
      event.category === "risk-change" ||
      event.category === "finding-change" ||
      event.category === "surface-change"
    ) {
      driftEvents += 1;
    }

    if (event.severity !== "safe") {
      latestAttention = event;
    }
  }

  return {
    critical,
    highRisk,
    risky,
    safe,
    actionEvents,
    boundaryEvents,
    driftEvents,
    latestAttention,
    attentionActions: [...attentionActions.values()]
      .sort((left, right) => {
        return (
          severityWeight(right.severity) - severityWeight(left.severity) ||
          right.count - left.count ||
          right.failed - left.failed
        );
      })
      .slice(0, 3),
    attentionActors: [...attentionActors.values()]
      .sort((left, right) => {
        return (
          severityWeight(right.severity) - severityWeight(left.severity) ||
          right.count - left.count ||
          right.actions.size - left.actions.size
        );
      })
      .slice(0, 3)
      .map((entry) => ({
        actorLabel: entry.actorLabel,
        count: entry.count,
        severity: entry.severity,
        actions: [...entry.actions]
      }))
  };
}

function eventKey(event: AuditEvent): string {
  return [
    event.timestamp,
    event.source,
    event.category,
    event.status ?? "",
    event.action ?? "",
    event.target ?? "",
    event.message
  ].join("::");
}

function renderTimelineEntry(entry: TimelineEntry): string[] {
  const headline = timelineHeadline(entry);
  const lines = [
    `${severityIcon(entry.primary.severity)} [${formatTimestamp(entry.primary.timestamp)}] ${headline}`
  ];

  const detail = timelineDetail(entry);
  if (detail && detail !== headline) {
    lines.push(`   📝 ${detail}`);
  }

  if (entry.primary.target) {
    lines.push(`   📍 发生在: ${displayUserPath(entry.primary.target)}`);
  }

  const feedPath =
    typeof entry.primary.evidence?.feedPath === "string" &&
    entry.primary.evidence.feedPath.trim().length > 0
      ? displayUserPath(entry.primary.evidence.feedPath)
      : undefined;
  if (feedPath) {
    lines.push(`   🧷 来源日志: ${feedPath}`);
  }

  if (entry.primary.recommendation) {
    lines.push(`   🔧 TraceRoot 建议先做: ${entry.primary.recommendation}`);
  }

  return lines;
}

function normalizeTargetFilter(target?: string): string | undefined {
  if (!target) {
    return undefined;
  }

  return path.resolve(target);
}

async function printLogs(
  runtime: CliRuntime,
  options: {
    target?: string;
    severity?: AuditSeverity;
    today?: boolean;
    limit?: number;
    header?: boolean;
    hostScope?: boolean;
  }
): Promise<AuditEvent[]> {
  const result = await readAuditEvents({
    target: options.target,
    severity: options.severity,
    today: options.today,
    limit: options.limit
  });
  const eventsAscending = [...result.events].reverse();
  const timelineEntries = buildTimelineEntries(eventsAscending);

  if (options.header !== false) {
    const summary = summarizeEvents(eventsAscending);
    const lines = [
      "TraceRoot Audit Logs",
      "====================",
      "",
      `🗂 审计日志位置: ${displayUserPath(result.paths.eventsPath)}`
    ];

    if (options.hostScope) {
      lines.push("🖥 正在查看: 整机陪跑时间线");
    } else if (options.target) {
      lines.push(`🎯 正在查看: ${displayUserPath(options.target)}`);
    }

    if (options.severity) {
      lines.push(`🚦 风险过滤: ${options.severity}`);
    }

    if (options.today) {
      lines.push("📅 时间范围: 今天");
    }

    lines.push(
      `📚 本次显示 ${eventsAscending.length} 条审计记录`,
      `🧾 对你来说更像 ${timelineEntries.length} 件完整的事`,
      `🧮 风险概览: 🚨 ${summary.critical} / 🛑 ${summary.highRisk} / ⚠️ ${summary.risky} / 🟢 ${summary.safe}`,
      `🎬 动作记录: ${summary.actionEvents} 条`,
      `🧱 边界与漂移: ${summary.boundaryEvents} 条边界漂移，${summary.driftEvents} 条整体变化`,
      ""
    );

    if (summary.latestAttention) {
      lines.push("👀 当前最值得注意的事情：");
      lines.push(`- ${eventHeadline(summary.latestAttention)}`);
      const detail = eventDetail(summary.latestAttention);
      if (detail && detail !== eventHeadline(summary.latestAttention)) {
        lines.push(`- 说明：${detail}`);
      }
      if (summary.latestAttention.recommendation) {
        lines.push(`- 建议：${summary.latestAttention.recommendation}`);
      }
      lines.push("");
    }

    if (summary.attentionActions.length > 0) {
      lines.push("🔥 今天最值得留意的动作：");
      for (const action of summary.attentionActions) {
        const prefix = severityIcon(action.severity);
        const failureSuffix = action.failed > 0 ? `，其中 ${action.failed} 次没有完成` : "";
        lines.push(`- ${prefix} ${action.actionLabel}：出现了 ${action.count} 次${failureSuffix}`);
      }
      lines.push("");
    } else if (summary.actionEvents === 0) {
      lines.push(
        "🫶 今天还没有触发值得单独提醒的 agent 动作。",
        "   TraceRoot 目前主要在盯边界有没有重新变宽，以及新的风险信号有没有冒出来。",
        ""
      );
    }

    if (summary.attentionActors.length > 0) {
      lines.push("🧭 今天这些 agent 最值得你看一眼：");
      for (const actor of summary.attentionActors) {
        const prefix = severityIcon(actor.severity);
        lines.push(
          `- ${prefix} ${actor.actorLabel}：出现了 ${actor.count} 次值得留意的动作（${actor.actions.slice(0, 2).join("、")}）`
        );
      }
      lines.push("");
    }

    lines.push("📘 最近发生的事：", "");

    runtime.io.stdout(`${lines.join("\n")}\n`);
  }

  if (eventsAscending.length === 0) {
    runtime.io.stdout(
      "🟢 这条时间线里还没有符合条件的审计记录。\n先运行 `traceroot-audit doctor --watch`，TraceRoot 才会开始陪跑并留下本地审计轨迹。\n"
    );
    return [];
  }

  for (const entry of timelineEntries) {
    runtime.io.stdout(`${renderTimelineEntry(entry).join("\n")}\n`);
  }

  return eventsAscending;
}

export function registerLogsCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("logs")
    .description("Review the local runtime audit timeline that TraceRoot recorded on this machine.")
    .argument("[target]", "target path to filter logs for")
    .option("--target <path>", "same as the positional target filter")
    .addOption(
      new Option("--severity <severity>", "show only one severity level").choices([
        "safe",
        "risky",
        "high-risk",
        "critical"
      ])
    )
    .option("--today", "show only events from today")
    .addOption(
      new Option("--limit <count>", "number of recent events to show")
        .default("20")
    )
    .option("--tail", "keep polling and print new events as they arrive")
    .option("--all", "show the full machine-wide audit timeline instead of resuming the last doctor target")
    .addOption(
      new Option("--interval <seconds>", "when used with --tail, seconds between refreshes")
        .default("2")
    )
    .action(async (targetArg: string | undefined, options: LogsOptions) => {
      let target = normalizeTargetFilter(options.target ?? targetArg);
      let hostScope = false;
      if (!target && !options.all) {
        const recentContext = await loadRecentDoctorContext();
        if (recentContext?.scope === "host") {
          hostScope = true;
          runtime.io.stdout("🧠 TraceRoot 先帮你继续看上次整机陪跑的时间线。\n\n");
        } else {
          const recentTarget = recentContext?.scope === "target"
            ? recentContext.targetPath
            : await loadRecentDoctorTarget();
          if (recentTarget) {
            target = normalizeTargetFilter(recentTarget);
            runtime.io.stdout(
              `🧠 TraceRoot 先帮你继续看上次陪跑的 target：${recentTargetLabel(recentTarget)}。\n\n`
            );
          }
        }
      }
      const limit = Number.parseInt(options.limit, 10);
      const intervalSeconds = Number.parseInt(options.interval, 10);

      if (!Number.isInteger(limit) || limit <= 0) {
        runtime.io.stderr("`--limit` must be a positive integer.\n");
        runtime.exitCode = 1;
        return;
      }

      if (!Number.isInteger(intervalSeconds) || intervalSeconds <= 0) {
        runtime.io.stderr("`--interval` must be a positive integer number of seconds.\n");
        runtime.exitCode = 1;
        return;
      }

      const initialEvents = await printLogs(runtime, {
        target,
        severity: options.severity,
        today: options.today,
        limit,
        hostScope
      });

      if (!options.tail) {
        return;
      }

      runtime.io.stdout(
        `\n💓 实时查看已开启。TraceRoot 每 ${intervalSeconds}s 会刷新一次新的审计事件，按 Ctrl+C 可以停止。\n\n`
      );

      const seen = new Set(initialEvents.map(eventKey));

      while (true) {
        await sleep(intervalSeconds * 1000);
        const result = await readAuditEvents({
          target,
          severity: options.severity,
          today: options.today
        });
        const nextEvents = [...result.events]
          .reverse()
          .filter((event) => !seen.has(eventKey(event)));

        for (const event of nextEvents) {
          runtime.io.stdout(`${renderEvent(event).join("\n")}\n`);
          seen.add(eventKey(event));
        }
      }
    });
}
