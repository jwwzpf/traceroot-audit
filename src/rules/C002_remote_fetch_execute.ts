import type { Finding } from "../core/findings";
import { splitLines, truncateEvidence } from "../utils/text";
import type { Rule } from "./types";
import { isExecutableTextFile } from "./helpers";

const directPipePattern =
  /\b(?:curl|wget)\b.*https?:\/\/[^\s|]+.*\|\s*(?:bash|sh|zsh|python|node)\b/i;

const remoteExecPattern =
  /\b(?:exec|spawn|system|subprocess\.(?:run|Popen))\b.*https?:\/\//i;

const downloadPattern =
  /\b(?:curl|wget)\b.*https?:\/\/\S+.*(?:-o|--output|-O)\s+([^\s]+)/i;

const executePattern = /\b(?:bash|sh|zsh|python|node)\s+([^\s]+)/i;

export const c002RemoteFetchExecuteRule: Rule = {
  id: "C002",
  title: "Remote Fetch and Execute",
  severity: "critical",
  description:
    "Detects remote content being fetched and executed directly, or downloaded and executed shortly afterward.",
  whyItMatters:
    "Fetching remote code and executing it in one flow bypasses review and provenance checks, which makes supply-chain compromise and silent behavior changes much harder to detect.",
  howToFix:
    "Remove fetch-and-execute flows, pin and verify artifacts before use, and separate download, review, and execution steps.",
  async run(context) {
    const findings: Finding[] = [];

    for (const file of context.files.filter(isExecutableTextFile)) {
      const lines = splitLines(file.content);
      const evidence: Array<{ line: number; text: string }> = [];

      lines.forEach((line, index) => {
        if (directPipePattern.test(line) || remoteExecPattern.test(line)) {
          evidence.push({
            line: index + 1,
            text: line
          });
        }
      });

      for (let index = 0; index < lines.length; index += 1) {
        const downloadMatch = lines[index]?.match(downloadPattern);
        if (!downloadMatch) {
          continue;
        }

        const downloadedTarget = downloadMatch[1];
        for (let offset = 1; offset <= 6 && index + offset < lines.length; offset += 1) {
          const executeMatch = lines[index + offset]?.match(executePattern);
          if (!executeMatch) {
            continue;
          }

          const executedTarget = executeMatch[1];
          if (executedTarget === downloadedTarget) {
            evidence.push({
              line: index + 1,
              text: `${lines[index]} && ${lines[index + offset]}`
            });
            break;
          }
        }
      }

      if (evidence.length === 0) {
        continue;
      }

      findings.push({
        ruleId: "C002",
        severity: "critical",
        title: "Remote Fetch and Execute",
        message: "Remote fetch-and-execute pattern detected.",
        file: file.relativePath,
        line: evidence[0]?.line,
        evidence: evidence
          .slice(0, 2)
          .map((match) => truncateEvidence(match.text))
          .join(" | "),
        recommendation:
          "Remove remote fetch-and-execute behavior and require reviewed, pinned artifacts before execution."
      });
    }

    return findings;
  }
};
