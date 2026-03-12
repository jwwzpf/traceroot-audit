import { Command } from "commander";

import { loadHardeningProfile } from "../../hardening/profile";
import { writeApplyBundle } from "../../hardening/apply";
import { loadManifest } from "../../manifest/loader";
import { resolveTarget } from "../../utils/files";

import type { CliRuntime } from "../index";

export function registerApplyCommand(program: Command, runtime: CliRuntime): void {
  program
    .command("apply")
    .description(
      "Generate safer companion patch files from an approved hardening profile."
    )
    .argument("[target]", "directory or file whose approved profile should be applied", ".")
    .action(async (target: string) => {
      const resolvedTarget = await resolveTarget(target);
      const hardeningProfileResult = await loadHardeningProfile(resolvedTarget.rootDir);

      if (!hardeningProfileResult.profile) {
        runtime.io.stderr(
          [
            "No saved hardening profile was found for this target.",
            "Run `traceroot-audit harden` first so TraceRoot can learn the workflows and boundary you approved."
          ].join("\n") + "\n"
        );
        runtime.exitCode = 1;
        return;
      }

      const manifestLoadResult = await loadManifest(resolvedTarget.rootDir);

      const bundle = await writeApplyBundle({
        rootDir: resolvedTarget.rootDir,
        profile: hardeningProfileResult.profile,
        manifestPathHint: manifestLoadResult.manifestPath
      });

      const lines = [
        "TraceRoot Audit Apply",
        "=====================",
        "",
        `🎯 Target: ${target}`,
        `🛡️ Approved workflows: ${hardeningProfileResult.profile.selectedIntents
          .map((intent) => intent.title)
          .join(", ")}`,
        "",
        "✨ Generated safer companion files:",
        `- 📜 Recommended manifest: ${bundle.manifestPath}`,
        `- 🧭 Apply plan: ${bundle.planPath}`
      ];

      if (bundle.envExamplePath) {
        lines.push(`- 🔐 Runtime env template: ${bundle.envExamplePath}`);
      }

      if (bundle.composeOverridePath) {
        lines.push(`- 🌐 Compose override: ${bundle.composeOverridePath}`);
      }

      if (bundle.tapPlanPath && bundle.tapWrapperDir) {
        lines.push(`- 🎬 Action audit guide: ${bundle.tapPlanPath}`);
        lines.push(`- 🧷 Ready-to-use command hooks: ${bundle.tapWrapperDir}`);
      }

      lines.push("", "🚀 Best next steps:");

      if (bundle.movedSecrets.length > 0) {
        lines.push(
          `- Move unrelated secrets out of the live runtime env: ${bundle.movedSecrets.join(", ")}`
        );
      }

      if (bundle.composeOverridePath && bundle.composeSourcePath) {
        lines.push(
          `- Re-start the runtime with the safer override: docker compose -f ${bundle.composeSourcePath} -f ${bundle.composeOverridePath} up -d`
        );
      } else {
        lines.push("- Review your runtime binding and keep it on localhost if possible.");
      }

      if (bundle.tapPlanPath && bundle.tapWrappers.length > 0) {
        lines.push(
          `- Switch the highest-risk skill/tool commands to the ${bundle.tapWrappers.length} prepared TraceRoot command hook${bundle.tapWrappers.length === 1 ? "" : "s"} listed in ${bundle.tapPlanPath}.`
        );
      }

      lines.push(
        `- Compare your active manifest with ${bundle.manifestPath} and carry over the reduced capability set.`
      );

      runtime.io.stdout(`${lines.join("\n")}\n`);
    });
}
