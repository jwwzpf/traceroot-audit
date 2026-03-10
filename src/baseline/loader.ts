import { access, readFile } from "node:fs/promises";
import path from "node:path";

import { ZodError } from "zod";

import {
  traceRootBaselineSchema,
  type TraceRootBaseline
} from "./schema";

const defaultBaselineFileName = "traceroot.baseline.json";

export interface LoadedBaseline {
  baseline: TraceRootBaseline | null;
  baselinePath: string | null;
  error?: string;
}

export async function loadBaseline(
  rootDir: string,
  explicitPath?: string
): Promise<LoadedBaseline> {
  const baselinePath = explicitPath
    ? path.resolve(explicitPath)
    : path.join(rootDir, defaultBaselineFileName);

  try {
    await access(baselinePath);
  } catch {
    return {
      baseline: null,
      baselinePath: explicitPath ? baselinePath : null,
      error: explicitPath ? `Baseline file not found: ${baselinePath}` : undefined
    };
  }

  try {
    const content = await readFile(baselinePath, "utf8");
    const baseline = traceRootBaselineSchema.parse(JSON.parse(content));

    return {
      baseline,
      baselinePath
    };
  } catch (error) {
    if (error instanceof ZodError) {
      return {
        baseline: null,
        baselinePath,
        error: error.issues
          .map((issue) => `${issue.path.join(".") || "root"}: ${issue.message}`)
          .join("; ")
      };
    }

    return {
      baseline: null,
      baselinePath,
      error: error instanceof Error ? error.message : "Baseline could not be loaded."
    };
  }
}

export function getDefaultBaselineFileName(): string {
  return defaultBaselineFileName;
}
