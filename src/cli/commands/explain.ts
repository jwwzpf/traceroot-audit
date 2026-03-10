import { Command, InvalidArgumentError } from "commander";

import { builtInRuleMap } from "../../rules";

import type { CliRuntime } from "../index";

export function registerExplainCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("explain")
    .description("Explain a built-in rule and how to remediate it.")
    .argument("<rule-id>", "rule identifier, for example C002")
    .action((ruleId: string) => {
      const normalizedRuleId = ruleId.toUpperCase();
      const rule = builtInRuleMap.get(normalizedRuleId);

      if (!rule) {
        throw new InvalidArgumentError(`Unknown rule: ${ruleId}`);
      }

      const lines = [
        `${rule.id} ${rule.title}`,
        `${"=".repeat(rule.id.length + rule.title.length + 1)}`,
        "",
        `Severity: ${rule.severity}`,
        "",
        "What it means:",
        rule.description,
        "",
        "Why it matters:",
        rule.whyItMatters,
        "",
        "How to fix it:",
        rule.howToFix
      ];

      runtime.io.stdout(`${lines.join("\n")}\n`);
    });
}
