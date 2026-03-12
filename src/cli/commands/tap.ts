import path from "node:path";
import { spawn } from "node:child_process";

import { Command, Option } from "commander";

import { appendAuditEvents } from "../../audit/store";
import type { AuditEvent, AuditSeverity } from "../../audit/types";

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

function formatCommand(args: string[]): string {
  return args
    .map((arg) => (/\s/.test(arg) ? JSON.stringify(arg) : arg))
    .join(" ");
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
      const commandDisplay = formatCommand(command);
      const startMessage =
        options.message ??
        `Agent is attempting a ${options.severity} action: ${options.action}.`;

      const introLines = [
        `${alertIcon(options.severity)} TraceRoot Action Tap`,
        `🧩 Action: ${options.action}`,
        `🎯 Target: ${target}`,
        `🛠 Command: ${commandDisplay}`
      ];

      if (options.severity === "high-risk" || options.severity === "critical") {
        introLines.push("⚡ This action is being recorded as a high-signal runtime audit event.");
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
              ? `Agent action succeeded: ${options.action}.`
              : `Agent action failed: ${options.action}.`,
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
          `${success ? "✅" : "❌"} TraceRoot recorded ${options.action} as ${success ? "succeeded" : "failed"}.\n`
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
            message: `Agent action failed before completion: ${options.action}.`,
            recommendation:
              options.recommendation ??
              "Review whether this command should remain wired into the runtime.",
            evidence: {
              command: command,
              error: message
            }
          }
        ]);
        runtime.io.stderr(`❌ Failed to run wrapped command: ${message}\n`);
        runtime.exitCode = 1;
      }
    });
}
