import { Command } from "commander";

import { builtInRules } from "../../rules";

import type { CliRuntime } from "../index";

export function registerRulesCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("rules")
    .description("List all built-in detection rules.")
    .action(() => {
      const lines = [
        "TraceRoot Audit Rules",
        "=====================",
        ""
      ];

      for (const rule of builtInRules) {
        lines.push(
          `[${rule.severity.toUpperCase()}] ${rule.id} ${rule.title}`,
          `  ${rule.description}`,
          ""
        );
      }

      runtime.io.stdout(`${lines.join("\n").trimEnd()}\n`);
    });
}
