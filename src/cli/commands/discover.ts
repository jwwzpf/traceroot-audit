import { Command, Option } from "commander";

import { discoverHost, discoverTarget } from "../../core/discovery";
import {
  renderHostDiscoveryHumanOutput,
  renderHostDiscoveryJsonOutput,
  renderDiscoveryHumanOutput,
  renderDiscoveryJsonOutput
} from "../../core/output";

import type { CliRuntime } from "../index";

export function registerDiscoverCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("discover")
    .description(
      "Inspect a local repo and recommend what to scan: agent project, skill/tool package, or runtime config."
    )
    .argument("[target]", "directory or file to inspect", ".")
    .addOption(
      new Option("--format <format>", "output format")
        .choices(["human", "json"])
        .default("human")
    )
    .option(
      "--host",
      "search common agent/runtime locations on this machine instead of only the current path"
    )
    .action(
      async (
        target: string,
        options: {
          format: "human" | "json";
          host?: boolean;
        }
      ) => {
        const output = options.host
          ? (() => {
              const resultPromise = discoverHost();
              return resultPromise.then((result) =>
                options.format === "json"
                  ? renderHostDiscoveryJsonOutput(result)
                  : renderHostDiscoveryHumanOutput(result)
              );
            })()
          : (() => {
              const resultPromise = discoverTarget(target);
              return resultPromise.then((result) =>
                options.format === "json"
                  ? renderDiscoveryJsonOutput(result)
                  : renderDiscoveryHumanOutput(result)
              );
            })();

        runtime.io.stdout(await output);
      }
    );
}
