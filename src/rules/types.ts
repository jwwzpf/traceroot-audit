import type { TraceRootManifest } from "../manifest/schema";
import type { Finding } from "../core/findings";
import type { Severity } from "../core/severities";

export type ScanTargetType = "directory" | "file";

export interface ScannableFile {
  absolutePath: string;
  relativePath: string;
  extension: string;
  content: string;
}

export interface ScanContext {
  target: string;
  targetPath: string;
  rootDir: string;
  targetType: ScanTargetType;
  files: ScannableFile[];
  manifest: TraceRootManifest | null;
  manifestPath: string | null;
  manifestError?: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  whyItMatters: string;
  howToFix: string;
  run(context: ScanContext): Promise<Finding[]>;
}
