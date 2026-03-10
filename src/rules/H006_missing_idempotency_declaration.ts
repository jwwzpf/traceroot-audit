import type { Rule } from "./types";
import { destructivePatterns, firstSignalInFile } from "./helpers";

export const h006MissingIdempotencyDeclarationRule: Rule = {
  id: "H006",
  title: "No Replay / Idempotency Declaration",
  severity: "high",
  description:
    "Flags side-effecting skills when trust metadata does not say how replay or repeated execution behaves.",
  whyItMatters:
    "Without an idempotency declaration, retries or duplicate invocations can trigger repeated deletes, sends, or purchases with unclear recovery behavior.",
  howToFix:
    "Declare `idempotency` in the manifest as `idempotent`, `non_idempotent`, or `not_applicable` and document replay expectations for side effects.",
  async run(context) {
    const destructiveSignal = context.files
      .map((file) => firstSignalInFile(file, destructivePatterns))
      .find(Boolean);

    const sideEffectsPresent =
      context.manifest?.side_effects === true ||
      Boolean(destructiveSignal) ||
      Boolean(
        context.manifest?.capabilities.some((capability) =>
          ["email", "payments"].includes(capability)
        )
      );

    if (!sideEffectsPresent) {
      return [];
    }

    if (
      context.manifest?.idempotency &&
      context.manifest.idempotency !== "unknown"
    ) {
      return [];
    }

    const findingFile = context.manifestPath ?? destructiveSignal?.file ?? null;
    const findingLine = context.manifestPath ? undefined : destructiveSignal?.line;

    return [
      {
        ruleId: "H006",
        severity: "high",
        title: "No Replay / Idempotency Declaration",
        message:
          "Side-effecting behavior is present but trust metadata does not declare replay or idempotency behavior.",
        file: findingFile,
        line: findingLine,
        evidence:
          context.manifestPath && context.manifest
            ? `idempotency: ${context.manifest.idempotency ?? "missing"}`
            : destructiveSignal?.evidence,
        recommendation:
          "Declare idempotency in the manifest and document whether repeated execution is safe, unsafe, or not applicable."
      }
    ];
  }
};
