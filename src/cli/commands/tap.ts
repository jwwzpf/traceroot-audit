import path from "node:path";
import { spawn } from "node:child_process";

import { Command, Option } from "commander";

import { appendAuditEvents } from "../../audit/store";
import type { AuditEvent, AuditSeverity } from "../../audit/types";
import { actionLabel } from "../../audit/presentation";
import { displayUserPath } from "../../utils/paths";

import type { CliRuntime } from "../index";

interface TapOptions {
  action: string;
  severity: AuditSeverity;
  target?: string;
  runtime?: string;
  surfaceKind?: "runtime" | "skill" | "project";
  message?: string;
  recommendation?: string;
}

function now(): string {
  return new Date().toISOString();
}

function alertIcon(severity: AuditSeverity): string {
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

async function persistEvents(runtime: CliRuntime, events: AuditEvent[]): Promise<void> {
  try {
    await appendAuditEvents(events);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "unknown audit log write error";
    runtime.io.stderr(`⚠️ Could not write action audit events: ${message}\n`);
  }
}

function runWrappedCommand(commandAndArgs: string[]): Promise<{ code: number; signal: NodeJS.Signals | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(commandAndArgs[0]!, commandAndArgs.slice(1), {
      stdio: "inherit",
      env: process.env
    });

    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({
        code: code ?? 1,
        signal
      });
    });
  });
}

export function registerTapCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("tap")
    .description(
      "Wrap a real action so TraceRoot can record a runtime audit event before and after it runs."
    )
    .requiredOption("--action <name>", "high-value action label, e.g. send-email or delete-files")
    .addOption(
      new Option("--severity <severity>", "risk level for this action")
        .choices(["safe", "risky", "high-risk", "critical"])
        .default("risky")
    )
    .option("--target <path>", "runtime, skill, or project path associated with this action")
    .option("--runtime <name>", "runtime name shown in audit events")
    .addOption(
      new Option("--surface-kind <kind>", "surface kind associated with this action")
        .choices(["runtime", "skill", "project"])
    )
    .option("--message <text>", "custom action message to store in the audit log")
    .option("--recommendation <text>", "what the operator should review next")
    .passThroughOptions()
    .allowUnknownOption(true)
    .argument("<command...>", "real command to execute after the -- separator")
    .action(async (command: string[], options: TapOptions) => {
      const target = options.target ? path.resolve(options.target) : process.cwd();
      const startMessage =
        options.message ??
        `Agent 正在尝试一个${options.severity === "critical" ? "极高风险" : options.severity === "high-risk" ? "高风险" : options.severity === "risky" ? "有风险" : "安全"}动作：${actionLabel(options.action)}。`;

      const introLines = [
        `${alertIcon(options.severity)} TraceRoot 正在接手一次动作审计`,
        `🧩 当前动作：${actionLabel(options.action)}`,
        `🎯 所在位置：${displayUserPath(target)}`
      ];

      if (options.severity === "high-risk" || options.severity === "critical") {
        introLines.push("⚡ 这次动作会被单独记进高风险审计时间线。");
      }

      runtime.io.stdout(`${introLines.join("\n")}\n`);

      await persistEvents(runtime, [
        {
          timestamp: now(),
          severity: options.severity,
          category: "action-event",
          source: "tap-wrapper",
          target,
          runtime: options.runtime,
          surfaceKind: options.surfaceKind,
          action: options.action,
          status: "attempted",
          message: startMessage,
          recommendation: options.recommendation,
          evidence: {
            command: command,
            cwd: process.cwd()
          }
        }
      ]);

      try {
        const result = await runWrappedCommand(command);
        const success = result.code === 0;

        await persistEvents(runtime, [
          {
            timestamp: now(),
            severity: success ? "safe" : options.severity,
            category: "action-event",
            source: "tap-wrapper",
            target,
            runtime: options.runtime,
            surfaceKind: options.surfaceKind,
            action: options.action,
            status: success ? "succeeded" : "failed",
            message: success
              ? `Agent 动作执行成功：${actionLabel(options.action)}。`
              : `Agent 动作执行失败：${actionLabel(options.action)}。`,
            recommendation: success
              ? undefined
              : options.recommendation ?? "Review the command output and decide whether this action should stay enabled.",
            evidence: {
              command: command,
              exitCode: result.code,
              signal: result.signal
            }
          }
        ]);

        runtime.io.stdout(
          [
            `${success ? "✅" : "❌"} TraceRoot 已经记下这次动作：${actionLabel(options.action)}`,
            success
              ? "📚 之后想回看这次动作做了什么，直接运行：traceroot-audit logs"
              : "📚 这次失败也已经记进审计时间线里了，之后可以直接运行：traceroot-audit logs"
          ].join("\n") + "\n"
        );
        runtime.exitCode = result.code;
      } catch (error) {
        const message = error instanceof Error ? error.message : "unknown execution error";
        await persistEvents(runtime, [
          {
            timestamp: now(),
            severity: options.severity,
            category: "action-event",
            source: "tap-wrapper",
            target,
            runtime: options.runtime,
            surfaceKind: options.surfaceKind,
            action: options.action,
            status: "failed",
            message: `Agent 动作还没真正执行完就失败了：${actionLabel(options.action)}。`,
            recommendation:
              options.recommendation ??
              "回头检查一下，这个动作还应不应该继续留在 agent 的执行路径里。",
            evidence: {
              command: command,
              error: message
            }
          }
        ]);
        runtime.io.stderr(`❌ 这次动作没有执行成功：${message}\n`);
        runtime.exitCode = 1;
      }
    });
}
