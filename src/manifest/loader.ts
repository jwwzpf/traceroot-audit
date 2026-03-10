import { access, readFile } from "node:fs/promises";
import path from "node:path";

import YAML from "yaml";
import { ZodError } from "zod";

import { traceRootManifestSchema, type TraceRootManifest } from "./schema";

const manifestNames = [
  "traceroot.manifest.json",
  "traceroot.manifest.yaml",
  "traceroot.manifest.yml"
];

export interface ManifestLoadResult {
  manifest: TraceRootManifest | null;
  manifestPath: string | null;
  error?: string;
}

function formatValidationError(error: ZodError): string {
  return error.issues
    .map((issue) => `${issue.path.join(".") || "root"}: ${issue.message}`)
    .join("; ");
}

export async function loadManifest(rootDir: string): Promise<ManifestLoadResult> {
  for (const manifestName of manifestNames) {
    const absolutePath = path.join(rootDir, manifestName);

    try {
      await access(absolutePath);
    } catch {
      continue;
    }

    try {
      const content = await readFile(absolutePath, "utf8");
      const rawValue = manifestName.endsWith(".json")
        ? JSON.parse(content)
        : YAML.parse(content);
      const manifest = traceRootManifestSchema.parse(rawValue);

      return {
        manifest,
        manifestPath: manifestName
      };
    } catch (error) {
      if (error instanceof ZodError) {
        return {
          manifest: null,
          manifestPath: manifestName,
          error: formatValidationError(error)
        };
      }

      return {
        manifest: null,
        manifestPath: manifestName,
        error: error instanceof Error ? error.message : "Manifest could not be loaded."
      };
    }
  }

  return {
    manifest: null,
    manifestPath: null
  };
}
