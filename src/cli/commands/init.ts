import { Command, Option } from "commander";

import {
  writeManifestTemplate,
  type ManifestFormat
} from "../../manifest/template";

import type { CliRuntime } from "../index";

export function registerInitCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("init")
    .description("Generate a starter trust manifest in the target directory.")
    .argument("[target]", "directory to initialize", ".")
    .addOption(
      new Option("--format <format>", "manifest format")
        .choices(["json", "yaml"])
        .default("json")
    )
    .option("--force", "overwrite an existing manifest")
    .action(
      async (
        target: string,
        options: { format: ManifestFormat; force?: boolean }
      ) => {
        const result = await writeManifestTemplate(target, {
          format: options.format,
          force: options.force === true
        });

        runtime.io.stdout(
          [
            "TraceRoot Audit Init",
            "====================",
            "",
            `✨ Created: ${result.manifestRelativePath}`,
            `📄 Path: ${result.manifestFilePath}`,
            "",
            "Next steps:",
            "- Review `capabilities`, `risk_level`, and `side_effects`.",
            `- Run \`traceroot-audit scan ${target}\` to validate the project.`
          ].join("\n") + "\n"
        );
      }
    );
}
