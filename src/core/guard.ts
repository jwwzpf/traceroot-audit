import {
  createFindingFingerprint,
  type FindingSummary,
  type ScanResult
} from "./findings";
import type { HostDiscoveryResult } from "./discovery";

export interface GuardScanSnapshot {
  kind: "scan";
  target: string;
  riskScore: number;
  summary: FindingSummary;
  findingFingerprints: string[];
}

export interface GuardHostCandidateSnapshot {
  absolutePath: string;
  displayPath: string;
  tier: "best-first" | "possible";
  categoryLabel: string;
  recommendedAction: "scan" | "harden";
  recommendedActionLabel: string;
  recommendedCommand: string;
}

export interface GuardHostSnapshot {
  kind: "host";
  candidates: GuardHostCandidateSnapshot[];
}

export interface ScanGuardDiff {
  changed: boolean;
  riskChanged: boolean;
  riskDelta: number;
  newFindingCount: number;
  resolvedFindingCount: number;
}

export interface HostGuardDiff {
  changed: boolean;
  newBestFirst: GuardHostCandidateSnapshot[];
  newPossible: GuardHostCandidateSnapshot[];
  removed: GuardHostCandidateSnapshot[];
  promotedToBestFirst: GuardHostCandidateSnapshot[];
}

export function createScanSnapshot(result: ScanResult): GuardScanSnapshot {
  return {
    kind: "scan",
    target: result.target,
    riskScore: result.riskScore,
    summary: result.summary,
    findingFingerprints: result.findings.map(createFindingFingerprint)
  };
}

export function createHostSnapshot(result: HostDiscoveryResult): GuardHostSnapshot {
  return {
    kind: "host",
    candidates: result.candidates.map((candidate) => ({
      absolutePath: candidate.absolutePath,
      displayPath: candidate.displayPath,
      tier: candidate.tier,
      categoryLabel: candidate.categoryLabel,
      recommendedAction: candidate.recommendedAction,
      recommendedActionLabel: candidate.recommendedActionLabel,
      recommendedCommand: candidate.recommendedCommand
    }))
  };
}

export function diffScanSnapshots(
  previous: GuardScanSnapshot,
  current: GuardScanSnapshot
): ScanGuardDiff {
  const previousFingerprints = new Set(previous.findingFingerprints);
  const currentFingerprints = new Set(current.findingFingerprints);

  let newFindingCount = 0;
  for (const fingerprint of currentFingerprints) {
    if (!previousFingerprints.has(fingerprint)) {
      newFindingCount += 1;
    }
  }

  let resolvedFindingCount = 0;
  for (const fingerprint of previousFingerprints) {
    if (!currentFingerprints.has(fingerprint)) {
      resolvedFindingCount += 1;
    }
  }

  const riskDelta = Number((current.riskScore - previous.riskScore).toFixed(1));
  const riskChanged = riskDelta !== 0;

  return {
    changed: riskChanged || newFindingCount > 0 || resolvedFindingCount > 0,
    riskChanged,
    riskDelta,
    newFindingCount,
    resolvedFindingCount
  };
}

export function diffHostSnapshots(
  previous: GuardHostSnapshot,
  current: GuardHostSnapshot
): HostGuardDiff {
  const previousMap = new Map(
    previous.candidates.map((candidate) => [candidate.absolutePath, candidate])
  );
  const currentMap = new Map(
    current.candidates.map((candidate) => [candidate.absolutePath, candidate])
  );

  const newBestFirst: GuardHostCandidateSnapshot[] = [];
  const newPossible: GuardHostCandidateSnapshot[] = [];
  const promotedToBestFirst: GuardHostCandidateSnapshot[] = [];
  const removed: GuardHostCandidateSnapshot[] = [];

  for (const candidate of current.candidates) {
    const previousCandidate = previousMap.get(candidate.absolutePath);

    if (!previousCandidate) {
      if (candidate.tier === "best-first") {
        newBestFirst.push(candidate);
      } else {
        newPossible.push(candidate);
      }
      continue;
    }

    if (
      previousCandidate.tier !== "best-first" &&
      candidate.tier === "best-first"
    ) {
      promotedToBestFirst.push(candidate);
    }
  }

  for (const candidate of previous.candidates) {
    if (!currentMap.has(candidate.absolutePath)) {
      removed.push(candidate);
    }
  }

  return {
    changed:
      newBestFirst.length > 0 ||
      newPossible.length > 0 ||
      promotedToBestFirst.length > 0 ||
      removed.length > 0,
    newBestFirst,
    newPossible,
    promotedToBestFirst,
    removed
  };
}
