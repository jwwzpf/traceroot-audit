import { loadBaseline } from "../baseline/loader";
import { loadManifest } from "../manifest/loader";
import { builtInRules } from "../rules";
import type { ScanContext } from "../rules/types";
import { discoverFiles, resolveTarget } from "../utils/files";
import {
  calculateRiskScore,
  createFindingFingerprint,
  sortFindings,
  summarizeFindings,
  type ScanResult
} from "./findings";

export interface ScanOptions {
  baselinePath?: string;
  useBaseline?: boolean;
}

export async function scanTarget(
  targetInput: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const resolvedTarget = await resolveTarget(targetInput);
  const files = await discoverFiles(resolvedTarget);
  const manifestLoadResult = await loadManifest(resolvedTarget.rootDir);
  const baselineLoadResult =
    options.useBaseline === false
      ? {
          baseline: null,
          baselinePath: null,
          error: undefined
        }
      : await loadBaseline(resolvedTarget.rootDir, options.baselinePath);

  const context: ScanContext = {
    target: targetInput,
    targetPath: resolvedTarget.absolutePath,
    rootDir: resolvedTarget.rootDir,
    targetType: resolvedTarget.type,
    files,
    manifest: manifestLoadResult.manifest,
    manifestPath: manifestLoadResult.manifestPath,
    manifestError: manifestLoadResult.error
  };

  const findings = (
    await Promise.all(builtInRules.map((rule) => rule.run(context)))
  ).flat();
  const baselineFingerprints = new Set(
    baselineLoadResult.baseline?.fingerprints.map((entry) => entry.fingerprint) ?? []
  );
  const filteredFindings =
    baselineFingerprints.size > 0
      ? findings.filter(
          (finding) => !baselineFingerprints.has(createFindingFingerprint(finding))
        )
      : findings;
  const orderedFindings = sortFindings(filteredFindings);
  const suppressedCount = findings.length - filteredFindings.length;

  return {
    target: targetInput,
    targetPath: resolvedTarget.absolutePath,
    riskScore: calculateRiskScore(orderedFindings),
    summary: summarizeFindings(orderedFindings),
    findings: orderedFindings,
    manifestPath: manifestLoadResult.manifestPath,
    baselinePath: baselineLoadResult.baselinePath,
    suppressedCount,
    baselineError: baselineLoadResult.error
  };
}
