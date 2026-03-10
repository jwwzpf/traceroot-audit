import type { Finding } from "../core/findings";
import type { Rule } from "./types";
import { allSignalsInFile, isConfigLikeFile } from "./helpers";

const publicBindPatterns = [
  /\b0\.0\.0\.0\b/,
  /\bhost\s*[:=]\s*["']?0\.0\.0\.0["']?/i,
  /["']?(?:0\.0\.0\.0:)?(?:3000|4000|5000|7860|8000|8080|11434|9000|9090):\d+["']?/
] as const;

const authHintPattern = /\b(auth|token|api[_-]?key|password|basic_auth|oauth)\b/i;

export const c001PublicRuntimeExposureRule: Rule = {
  id: "C001",
  title: "Public Runtime Exposure",
  severity: "critical",
  description:
    "Detects public bind addresses and obviously exposed runtime ports in local runtime configuration.",
  whyItMatters:
    "A local agent runtime that binds publicly can become reachable from outside the intended machine or network segment, which expands the blast radius of any runtime flaw or missing auth control.",
  howToFix:
    "Bind services to localhost by default, avoid public docker port mappings for agent runtimes, and require explicit authentication for any intentionally exposed endpoint.",
  async run(context) {
    const findings: Finding[] = [];

    for (const file of context.files.filter(isConfigLikeFile)) {
      const signals = allSignalsInFile(file, publicBindPatterns);
      if (signals.length === 0) {
        continue;
      }

      const exposedPortSignal = signals.find((signal) =>
        /:\d+/.test(signal.evidence)
      );
      if (exposedPortSignal && authHintPattern.test(file.content)) {
        continue;
      }

      findings.push({
        ruleId: "C001",
        severity: "critical",
        title: "Public Runtime Exposure",
        message:
          "Runtime appears to bind publicly or expose a known local runtime port without a clear authentication safeguard.",
        file: file.relativePath,
        line: signals[0]?.line,
        evidence: signals
          .slice(0, 3)
          .map((signal) => signal.evidence)
          .join(" | "),
        recommendation:
          "Restrict the runtime to localhost or a private interface and document explicit auth controls for any intentional exposure."
      });
    }

    return findings;
  }
};
