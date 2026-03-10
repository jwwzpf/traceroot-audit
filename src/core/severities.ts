export const severityWeights = {
  critical: 30,
  high: 15,
  medium: 5
} as const;

export type Severity = keyof typeof severityWeights;
export type FailOnSeverity = Severity | "none";

const severityRank: Record<Severity, number> = {
  medium: 1,
  high: 2,
  critical: 3
};

export function compareSeverity(left: Severity, right: Severity): number {
  return severityRank[left] - severityRank[right];
}

export function exceedsFailThreshold(
  severity: Severity,
  threshold: FailOnSeverity
): boolean {
  if (threshold === "none") {
    return false;
  }

  return compareSeverity(severity, threshold) >= 0;
}

export function severityLabel(severity: Severity): string {
  return severity.toUpperCase();
}
