import type { Rule } from "./types";
import {
  destructivePatterns,
  firstSignalInFile,
  safeguardPatterns
} from "./helpers";

export const c004DestructiveWithoutSafeguardsRule: Rule = {
  id: "C004",
  title: "Dangerous Destructive Capability Without Safeguards",
  severity: "critical",
  description:
    "Flags destructive or side-effect-heavy behavior when there is no obvious confirmation or safeguard declaration.",
  whyItMatters:
    "Delete, archive, purchase, email, or bulk-modify workflows can cause irreversible damage if they run without an approval or safety boundary.",
  howToFix:
    "Add explicit confirmation requirements or safeguards in the manifest and keep destructive actions behind a reviewable approval step.",
  async run(context) {
    const destructiveSignal = context.files
      .map((file) => firstSignalInFile(file, destructivePatterns))
      .find(Boolean);

    const hasManifestSafeguards =
      context.manifest?.confirmation_required === true ||
      Boolean(context.manifest?.safeguards?.length);

    const fileLevelSafeguard = context.files
      .map((file) => firstSignalInFile(file, safeguardPatterns))
      .find(Boolean);

    const capabilitySideEffects =
      context.manifest?.capabilities.some((capability) =>
        ["email", "payments"].includes(capability)
      ) ?? false;

    if ((!destructiveSignal && !capabilitySideEffects) || hasManifestSafeguards || fileLevelSafeguard) {
      return [];
    }

    return [
      {
        ruleId: "C004",
        severity: "critical",
        title: "Dangerous Destructive Capability Without Safeguards",
        message:
          "Destructive or side-effect-heavy behavior is present without an obvious confirmation or safeguard declaration.",
        file: destructiveSignal?.file ?? context.manifestPath,
        line: destructiveSignal?.line,
        evidence:
          destructiveSignal?.evidence ??
          `capabilities: ${(context.manifest?.capabilities ?? []).join(", ") || "none"}`,
        recommendation:
          "Declare `confirmation_required` or concrete safeguards in the manifest and keep destructive actions behind an explicit approval flow."
      }
    ];
  }
};
