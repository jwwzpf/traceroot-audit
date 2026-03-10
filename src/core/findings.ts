import { compareSeverity, exceedsFailThreshold, severityWeights, type FailOnSeverity, type Severity } from "./severities";

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  file: string | null;
  line?: number;
  evidence?: string;
  recommendation: string;
}

export interface FindingSummary {
  critical: number;
  high: number;
  medium: number;
  total: number;
}

export interface ScanResult {
  target: string;
  targetPath: string;
  riskScore: number;
  summary: FindingSummary;
  findings: Finding[];
  manifestPath: string | null;
  baselinePath: string | null;
  suppressedCount: number;
  baselineError?: string;
}

export function createFindingFingerprint(finding: Finding): string {
  return [
    finding.ruleId,
    finding.severity,
    finding.file ?? "",
    `${finding.line ?? ""}`,
    finding.evidence ?? ""
  ].join("::");
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severityDelta = compareSeverity(right.severity, left.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }

    const idDelta = left.ruleId.localeCompare(right.ruleId);
    if (idDelta !== 0) {
      return idDelta;
    }

    const fileDelta = (left.file ?? "").localeCompare(right.file ?? "");
    if (fileDelta !== 0) {
      return fileDelta;
    }

    return (left.line ?? 0) - (right.line ?? 0);
  });
}

export function summarizeFindings(findings: Finding[]): FindingSummary {
  return findings.reduce<FindingSummary>(
    (summary, finding) => {
      summary[finding.severity] += 1;
      summary.total += 1;
      return summary;
    },
    {
      critical: 0,
      high: 0,
      medium: 0,
      total: 0
    }
  );
}

export function calculateRiskScore(findings: Finding[]): number {
  const rawScore = findings.reduce(
    (score, finding) => score + severityWeights[finding.severity],
    0
  );

  return Math.min(10, Number((rawScore / 6).toFixed(1)));
}

export function shouldFail(findings: Finding[], threshold: FailOnSeverity): boolean {
  return findings.some((finding) => exceedsFailThreshold(finding.severity, threshold));
}
