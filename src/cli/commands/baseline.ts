import { Command } from "commander";

import { writeBaselineFile } from "../../baseline/writer";
import { scanTarget } from "../../core/scanner";

import type { CliRuntime } from "../index";

export function registerBaselineCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("baseline")
    .description("Record current findings into a baseline file for gradual adoption.")
    .argument("[target]", "directory or file to baseline", ".")
    .option(
      "--output <file>",
      "write baseline JSON to this path instead of traceroot.baseline.json"
    )
    .action(async (target: string, options: { output?: string }) => {
      const result = await scanTarget(target, {
        useBaseline: false
      });
      const baselineWrite = await writeBaselineFile(
        target,
        result.findings,
        options.output
      );

      runtime.io.stdout(
        [
          "TraceRoot Audit Baseline",
          "========================",
          "",
          `🧷 Created: ${baselineWrite.relativeOutputPath}`,
          `📄 Path: ${baselineWrite.baselinePath}`,
          `📦 Fingerprints recorded: ${baselineWrite.baseline.fingerprints.length}`,
          "",
          "Next steps:",
          `- Run \`traceroot-audit scan ${target}\` to report only new findings.`,
          "- Regenerate the baseline when you intentionally accept or fix existing findings."
        ].join("\n") + "\n"
      );
    });
}
