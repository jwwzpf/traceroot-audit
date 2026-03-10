import { Command, Option } from "commander";

import { scanTarget } from "../../core/scanner";
import {
  renderHumanOutput,
  renderJsonOutput,
  renderMarkdownOutput,
  renderSarifOutput
} from "../../core/output";
import { shouldFail } from "../../core/findings";
import type { FailOnSeverity } from "../../core/severities";

import type { CliRuntime } from "../index";

export function registerScanCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("scan")
    .description("Scan a local project, skill package, or runtime config.")
    .argument("[target]", "directory or file to scan", ".")
    .addOption(
      new Option("--format <format>", "output format")
        .choices(["human", "json", "sarif", "markdown"])
        .default("human")
    )
    .addOption(
      new Option("--fail-on <severity>", "exit non-zero at or above this severity")
        .choices(["critical", "high", "medium", "none"])
        .default("none")
    )
    .option(
      "--baseline <file>",
      "use a specific baseline file instead of auto-detecting traceroot.baseline.json"
    )
    .option("--ignore-baseline", "disable baseline loading for this scan")
    .option("--compact", "render a shorter markdown report optimized for PR comments")
    .action(
      async (
        target: string,
        options: {
          format: "human" | "json" | "sarif" | "markdown";
          failOn: FailOnSeverity;
          baseline?: string;
          ignoreBaseline?: boolean;
          compact?: boolean;
        }
      ) => {
      const result = await scanTarget(target, {
        baselinePath: options.baseline,
        useBaseline: options.ignoreBaseline !== true
      });
      const failed = shouldFail(result.findings, options.failOn);
      runtime.exitCode = failed ? 1 : 0;

      const output =
        options.format === "json"
          ? renderJsonOutput(result)
          : options.format === "sarif"
            ? renderSarifOutput(result)
            : options.format === "markdown"
              ? renderMarkdownOutput(result, options.failOn, failed, {
                compact: options.compact === true
              })
            : renderHumanOutput(result, options.failOn, failed);

      runtime.io.stdout(output);
    });
}
