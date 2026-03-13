import { Command, Option } from "commander";

import { runHostWatch, runTargetWatch } from "../watch";

import type { CliRuntime } from "../index";

interface GuardOptions {
  host?: boolean;
  includeCwd?: boolean;
  interval: string;
  cycles?: string;
  notifyWebhook?: string;
  notifyChannel?: string;
  notifyTarget?: string;
  notifyAccount?: string;
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
    .option(
      "--notify-webhook <url>",
      "also send high-risk action reminders to your webhook"
    )
    .option(
      "--notify-channel <channel>",
      "also send high-risk action reminders through one of your connected OpenClaw chat channels"
    )
    .option(
      "--notify-target <target>",
      "where TraceRoot should send those reminders in the chosen chat channel"
    )
    .option(
      "--notify-account <account>",
      "optional OpenClaw account name to use for that chat channel"
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
        await runHostWatch({
          runtime,
          intervalSeconds,
          maxCycles,
          includeCwd: options.includeCwd ?? false
        });
        return;
      }

      await runTargetWatch({
        runtime,
        target,
        intervalSeconds,
        maxCycles,
        notifications: {
          webhookUrl: options.notifyWebhook,
          openclawChannel: options.notifyChannel,
          openclawTarget: options.notifyTarget,
          openclawAccount: options.notifyAccount
        }
      });
    });
}
