import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { Command, Option } from "commander";

import { readAuditEvents } from "../../audit/store";
import type { AuditEvent, AuditSeverity } from "../../audit/types";
import { actionLabel } from "../../audit/presentation";
import { displayUserPath } from "../../utils/paths";

import type { CliRuntime } from "../index";

interface LogsOptions {
  target?: string;
  severity?: AuditSeverity;
  today?: boolean;
  limit: string;
  tail?: boolean;
  interval: string;
}

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

function summarizeEvents(events: AuditEvent[]): {
  critical: number;
  highRisk: number;
  risky: number;
  safe: number;
  actionEvents: number;
  latestAttention: AuditEvent | null;
} {
  let critical = 0;
  let highRisk = 0;
  let risky = 0;
  let safe = 0;
  let actionEvents = 0;
  let latestAttention: AuditEvent | null = null;

  for (const event of events) {
    if (event.severity === "critical") critical += 1;
    else if (event.severity === "high-risk") highRisk += 1;
    else if (event.severity === "risky") risky += 1;
    else safe += 1;

    if (event.category === "action-event") {
      actionEvents += 1;
    }

    if (!latestAttention && event.severity !== "safe") {
      latestAttention = event;
    }
  }

  return {
    critical,
    highRisk,
    risky,
    safe,
    actionEvents,
    latestAttention
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

function renderEvent(event: AuditEvent): string[] {
  const lines = [
    `${severityIcon(event.severity)} [${formatTimestamp(event.timestamp)}] ${categoryLabel(event)}`,
    `   ${event.message}`
  ];

  if (event.target) {
    lines.push(`   📍 位置: ${displayUserPath(event.target)}`);
  }

  if (event.action) {
    lines.push(`   🧩 动作: ${actionLabel(event.action)}`);
  }

  if (event.recommendation) {
    lines.push(`   🔧 建议: ${event.recommendation}`);
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
  }
): Promise<AuditEvent[]> {
  const result = await readAuditEvents({
    target: options.target,
    severity: options.severity,
    today: options.today,
    limit: options.limit
  });
  const eventsAscending = [...result.events].reverse();

  if (options.header !== false) {
    const summary = summarizeEvents(eventsAscending);
    const lines = [
      "TraceRoot Audit Logs",
      "====================",
      "",
      `🗂 审计日志位置: ${displayUserPath(result.paths.eventsPath)}`
    ];

    if (options.target) {
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
      `🧮 风险概览: 🚨 ${summary.critical} / 🛑 ${summary.highRisk} / ⚠️ ${summary.risky} / 🟢 ${summary.safe}`,
      `🎬 动作记录: ${summary.actionEvents} 条`,
      ""
    );

    if (summary.latestAttention) {
      lines.push("👀 当前最值得注意的事情：");
      lines.push(`- ${summary.latestAttention.message}`);
      if (summary.latestAttention.action) {
        lines.push(`- 动作：${actionLabel(summary.latestAttention.action)}`);
      }
      if (summary.latestAttention.recommendation) {
        lines.push(`- 建议：${summary.latestAttention.recommendation}`);
      }
      lines.push("");
    }

    runtime.io.stdout(`${lines.join("\n")}\n`);
  }

  if (eventsAscending.length === 0) {
    runtime.io.stdout(
      "🟢 这条时间线里还没有符合条件的审计记录。\n先运行 `traceroot-audit doctor --watch`，TraceRoot 才会开始陪跑并留下本地审计轨迹。\n"
    );
    return [];
  }

  for (const event of eventsAscending) {
    runtime.io.stdout(`${renderEvent(event).join("\n")}\n`);
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
    .addOption(
      new Option("--interval <seconds>", "when used with --tail, seconds between refreshes")
        .default("2")
    )
    .action(async (targetArg: string | undefined, options: LogsOptions) => {
      const target = normalizeTargetFilter(options.target ?? targetArg);
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
        limit
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
