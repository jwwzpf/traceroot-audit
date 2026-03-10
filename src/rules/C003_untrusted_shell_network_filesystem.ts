import type { Rule } from "./types";
import { firstSignalInFile, isExecutableTextFile } from "./helpers";

const shellPatterns = [
  /\bchild_process\b/,
  /\bexec\s*\(/,
  /\bspawn\s*\(/,
  /\bos\.system\s*\(/,
  /\bsubprocess\./,
  /\bshell:\s*true\b/i
] as const;

const networkPatterns = [
  /\bfetch\s*\(/,
  /\baxios\b/,
  /\brequests\./,
  /\burllib\./,
  /\bcurl\b/,
  /\bwget\b/,
  /https?:\/\//
] as const;

const filesystemPatterns = [
  /\bfs\./,
  /\breadFile\b/,
  /\bwriteFile\b/,
  /\bunlink\b/,
  /\bmkdir\b/,
  /\brm\s+-/i,
  /\bos\.remove\b/,
  /\bshutil\./
] as const;

export const c003UntrustedShellNetworkFilesystemRule: Rule = {
  id: "C003",
  title: "Untrusted Shell + Network + Filesystem Combo",
  severity: "critical",
  description:
    "Flags projects that combine shell, network, and filesystem capabilities without any trust manifest.",
  whyItMatters:
    "That capability combination is powerful enough to download, modify, and execute code locally, so it deserves explicit trust metadata and tighter review.",
  howToFix:
    "Add a trust manifest, narrow capabilities, and document why shell, network, and filesystem access are all required together.",
  async run(context) {
    if (context.manifest) {
      return [];
    }

    const candidateFiles = context.files.filter(isExecutableTextFile);
    const shellSignal = candidateFiles
      .map((file) => firstSignalInFile(file, shellPatterns))
      .find(Boolean);
    const networkSignal = candidateFiles
      .map((file) => firstSignalInFile(file, networkPatterns))
      .find(Boolean);
    const filesystemSignal = candidateFiles
      .map((file) => firstSignalInFile(file, filesystemPatterns))
      .find(Boolean);

    if (!shellSignal || !networkSignal || !filesystemSignal) {
      return [];
    }

    const evidence = [
      `shell: ${shellSignal.file}:${shellSignal.line} ${shellSignal.evidence}`,
      `network: ${networkSignal.file}:${networkSignal.line} ${networkSignal.evidence}`,
      `filesystem: ${filesystemSignal.file}:${filesystemSignal.line} ${filesystemSignal.evidence}`
    ].join(" | ");

    const file = shellSignal.file || networkSignal.file || filesystemSignal.file;
    const line = shellSignal.line || networkSignal.line || filesystemSignal.line;

    return [
      {
        ruleId: "C003",
        severity: "critical",
        title: "Untrusted Shell + Network + Filesystem Combo",
        message:
          "Shell, network, and filesystem primitives were detected together without trust metadata.",
        file,
        line,
        evidence,
        recommendation:
          "Add a valid `traceroot.manifest.*`, justify the combined capabilities, and remove any unnecessary primitive from the execution path."
      }
    ];
  }
};
