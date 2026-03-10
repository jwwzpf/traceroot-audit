import type { Rule } from "./types";
import {
  destructivePatterns,
  firstSignalInFile,
  longRunningPatterns
} from "./helpers";

export const h007MissingInterruptContractRule: Rule = {
  id: "H007",
  title: "Missing Interrupt / Stop Contract Declaration",
  severity: "high",
  description:
    "Flags destructive or long-running behavior when metadata does not declare whether the action can be interrupted safely.",
  whyItMatters:
    "Operators need to know whether a task can be stopped safely, especially when it changes files, sends requests, or holds open long-running runtime loops.",
  howToFix:
    "Declare `interrupt_support` in the manifest and describe the stop behavior, cleanup guarantees, and any partial side effects that may remain.",
  async run(context) {
    const longRunningSignal = context.files
      .map((file) => firstSignalInFile(file, longRunningPatterns))
      .find(Boolean);
    const destructiveSignal = context.files
      .map((file) => firstSignalInFile(file, destructivePatterns))
      .find(Boolean);

    const interruptRelevant =
      context.manifest?.side_effects === true ||
      Boolean(longRunningSignal) ||
      Boolean(destructiveSignal);

    if (!interruptRelevant) {
      return [];
    }

    if (
      context.manifest?.interrupt_support &&
      context.manifest.interrupt_support !== "unknown"
    ) {
      return [];
    }

    const evidenceSignal = destructiveSignal ?? longRunningSignal;
    const findingFile = context.manifestPath ?? evidenceSignal?.file ?? null;
    const findingLine = context.manifestPath ? undefined : evidenceSignal?.line;

    return [
      {
        ruleId: "H007",
        severity: "high",
        title: "Missing Interrupt / Stop Contract Declaration",
        message:
          "Destructive or long-running behavior is present but interrupt/stop support is not declared.",
        file: findingFile,
        line: findingLine,
        evidence:
          context.manifestPath && context.manifest
            ? `interrupt_support: ${context.manifest.interrupt_support ?? "missing"}`
            : evidenceSignal?.evidence,
        recommendation:
          "Declare `interrupt_support` in the manifest and describe whether a stop request is supported, unsupported, or not applicable."
      }
    ];
  }
};
