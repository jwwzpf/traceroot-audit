import type { Rule } from "./types";

const highRiskCapabilities = ["shell", "network", "filesystem", "browser", "email", "payments"];

export const h002OverbroadPermissionDeclarationRule: Rule = {
  id: "H002",
  title: "Overbroad Permission Declaration",
  severity: "high",
  description:
    "Flags manifests that declare too many high-risk primitives at once.",
  whyItMatters:
    "Broad capability sets increase the chance that a small bug or prompt injection can turn into data access, code execution, or unintended side effects.",
  howToFix:
    "Reduce capabilities to the smallest set required for the skill and split unrelated actions into separate, narrower tools.",
  async run(context) {
    if (!context.manifest) {
      return [];
    }

    const declared = context.manifest.capabilities.filter((capability) =>
      highRiskCapabilities.includes(capability)
    );

    const isOverbroad =
      declared.length >= 4 ||
      (declared.length >= 3 &&
        (declared.includes("email") || declared.includes("payments")));

    if (!isOverbroad) {
      return [];
    }

    return [
      {
        ruleId: "H002",
        severity: "high",
        title: "Overbroad Permission Declaration",
        message:
          "Manifest declares a broad set of high-risk capabilities for a single skill or runtime package.",
        file: context.manifestPath,
        evidence: `capabilities: ${declared.join(", ")}`,
        recommendation:
          "Narrow the manifest capability list and separate unrelated high-risk actions into smaller components."
      }
    ];
  }
};
