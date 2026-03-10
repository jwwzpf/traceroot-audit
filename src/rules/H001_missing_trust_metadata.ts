import type { Rule } from "./types";

export const h001MissingTrustMetadataRule: Rule = {
  id: "H001",
  title: "Missing Trust Metadata",
  severity: "high",
  description:
    "Checks whether a valid `traceroot.manifest.json` or YAML equivalent is present.",
  whyItMatters:
    "Without a manifest there is no compact way to evaluate capability intent, risk level, provenance, or expected side effects before a skill runs.",
  howToFix:
    "Add a valid `traceroot.manifest.json`, `traceroot.manifest.yaml`, or `traceroot.manifest.yml` with capabilities, risk, and side-effect declarations.",
  async run(context) {
    if (context.manifest) {
      return [];
    }

    return [
      {
        ruleId: "H001",
        severity: "high",
        title: "Missing Trust Metadata",
        message: context.manifestError
          ? "Trust metadata file was found but could not be validated."
          : "No trust metadata manifest was found.",
        file: context.manifestPath,
        evidence: context.manifestError,
        recommendation:
          "Add a valid `traceroot.manifest.json` or YAML equivalent at the scan root."
      }
    ];
  }
};
