import { writeFile } from "node:fs/promises";
import path from "node:path";

import type { Finding } from "../core/findings";
import { createFindingFingerprint } from "../core/findings";
import { resolveTarget } from "../utils/files";
import {
  getDefaultBaselineFileName
} from "./loader";
import type { TraceRootBaseline } from "./schema";

export interface WriteBaselineResult {
  baselinePath: string;
  relativeOutputPath: string;
  baseline: TraceRootBaseline;
}

export async function writeBaselineFile(
  targetInput: string,
  findings: Finding[],
  outputPath?: string
): Promise<WriteBaselineResult> {
  const resolvedTarget = await resolveTarget(targetInput);
  const targetDir =
    resolvedTarget.type === "directory"
      ? resolvedTarget.absolutePath
      : resolvedTarget.rootDir;
  const finalOutputPath = outputPath
    ? path.resolve(outputPath)
    : path.join(targetDir, getDefaultBaselineFileName());

  const baseline: TraceRootBaseline = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    target: targetInput,
    fingerprints: findings.map((finding) => ({
      fingerprint: createFindingFingerprint(finding),
      ruleId: finding.ruleId,
      severity: finding.severity,
      file: finding.file,
      line: finding.line
    }))
  };

  await writeFile(`${finalOutputPath}`, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");

  return {
    baselinePath: finalOutputPath,
    relativeOutputPath: path.relative(targetDir, finalOutputPath) || getDefaultBaselineFileName(),
    baseline
  };
}
