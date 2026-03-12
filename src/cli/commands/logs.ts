import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { Command, Option } from "commander";

import { readAuditEvents } from "../../audit/store";
import type { AuditEvent, AuditSeverity } from "../../audit/types";

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
      return "Watch started";
    case "watch-heartbeat":
      return "Watch heartbeat";
    case "risk-change":
      return "Risk changed";
    case "finding-change":
      return "Findings changed";
    case "boundary-drift":
      return "Boundary drift";
    case "surface-change":
      return "Surface changed";
    default:
      return event.category;
  }
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
    lines.push(`   📍 Target: ${event.target}`);
  }

  if (event.recommendation) {
    lines.push(`   🔧 Next: ${event.recommendation}`);
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
    const lines = [
      "TraceRoot Audit Logs",
      "====================",
      "",
      `🗂 Source: ${result.paths.eventsPath}`
    ];

    if (options.target) {
      lines.push(`🎯 Target filter: ${options.target}`);
    }

    if (options.severity) {
      lines.push(`🚦 Severity filter: ${options.severity}`);
    }

    if (options.today) {
      lines.push("📅 Time filter: today");
    }

    lines.push(`📚 Showing ${eventsAscending.length} event${eventsAscending.length === 1 ? "" : "s"}`, "");
    runtime.io.stdout(`${lines.join("\n")}\n`);
  }

  if (eventsAscending.length === 0) {
    runtime.io.stdout(
      "🟢 No audit events matched this filter yet.\nRun `traceroot-audit doctor --watch` to start leaving a local audit trail.\n"
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
        `\n💓 Tail mode is on. TraceRoot will print new audit events every ${intervalSeconds}s. Press Ctrl+C to stop.\n\n`
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
