import type { Finding } from "../core/findings";
import { extractUrls, isExternalUrl } from "../utils/urls";
import type { Rule } from "./types";
import { isManifestFile } from "./helpers";

interface PackageJsonMetadata {
  repository?: unknown;
  homepage?: unknown;
  bugs?: unknown;
  funding?: unknown;
}

const benignHosts = new Set(["registry.npmjs.org"]);

export const h004HardcodedExternalEndpointsRule: Rule = {
  id: "H004",
  title: "Hardcoded External Endpoints",
  severity: "high",
  description:
    "Detects hardcoded remote HTTP(S) endpoints in executable or configuration content.",
  whyItMatters:
    "Hardcoded external endpoints make remote control surfaces and data paths harder to review, rotate, or constrain with policy.",
  howToFix:
    "Move endpoints into reviewed configuration, prefer allowlisted domains, and avoid embedding raw remote script hosts directly in executable content.",
  async run(context) {
    const findings: Finding[] = [];

    for (const file of context.files) {
      if (isManifestFile(file) || file.relativePath.endsWith(".md")) {
        continue;
      }

      const metadataUrls = file.relativePath.endsWith("package.json")
        ? extractPackageMetadataUrls(file.content)
        : new Set<string>();
      const urls = extractUrls(file.content)
        .filter(isExternalUrl)
        .filter((url) => !isBenignUrl(url))
        .filter((url) => !metadataUrls.has(url));
      if (urls.length === 0) {
        continue;
      }

      findings.push({
        ruleId: "H004",
        severity: "high",
        title: "Hardcoded External Endpoints",
        message:
          "Hardcoded external endpoint detected in executable or configuration content.",
        file: file.relativePath,
        evidence: urls.slice(0, 3).join(" | "),
        recommendation:
          "Move remote endpoints into reviewed configuration or manifest metadata and keep execution paths on an explicit allowlist."
      });
    }

    return findings;
  }
};

function extractPackageMetadataUrls(content: string): Set<string> {
  try {
    const packageJson = JSON.parse(content) as PackageJsonMetadata;
    const knownMetadataUrls = [
      ...normalizePackageFieldUrls(packageJson.repository),
      ...normalizePackageFieldUrls(packageJson.homepage),
      ...normalizePackageFieldUrls(packageJson.bugs),
      ...normalizePackageFieldUrls(packageJson.funding)
    ].filter(isExternalUrl);

    return new Set(knownMetadataUrls);
  } catch {
    return new Set<string>();
  }
}

function isBenignUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return benignHosts.has(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function normalizePackageFieldUrls(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }

  if (Array.isArray(value)) {
    return value.flatMap((entry) => normalizePackageFieldUrls(entry));
  }

  if (value && typeof value === "object") {
    return Object.values(value).flatMap((entry) => normalizePackageFieldUrls(entry));
  }

  return [];
}
