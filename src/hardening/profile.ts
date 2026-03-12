import { access, readFile } from "node:fs/promises";
import path from "node:path";

import { z, ZodError } from "zod";

import { traceRootManifestSchema } from "../manifest/schema";

const selectedPoliciesSchema = z.object({
  outboundApproval: z.enum([
    "always-confirm",
    "confirm-high-risk",
    "allow-autonomous"
  ]),
  filesystemScope: z.enum(["no-write", "workspace-only", "broad-write"]),
  exposureMode: z.enum(["localhost-only", "lan-access"])
});

const selectedIntentSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1)
});

const hardeningProfileSchema = z
  .object({
    schemaVersion: z.number().int().positive().optional(),
    generatedAt: z.string().optional(),
    target: z.string().min(1),
    targetPath: z.string().min(1),
    surface: z.string().min(1),
    selectedIntents: z.array(selectedIntentSchema),
    selectedPolicies: selectedPoliciesSchema.optional(),
    currentCapabilities: z.array(z.string().min(1)),
    recommendedCapabilities: z.array(z.string().min(1)),
    extraCapabilities: z.array(z.string().min(1)),
    missingCapabilities: z.array(z.string().min(1)),
    approvalPolicy: z.string().min(1),
    fileWritePolicy: z.string().min(1),
    exposurePolicy: z.string().min(1),
    immediateActions: z.array(z.string().min(1)),
    secretExposure: z.array(
      z.object({
        variable: z.string().min(1),
        group: z.string().min(1),
        action: z.enum(["keep", "review", "remove"])
      })
    ),
    findingsSummary: z.object({
      critical: z.number().int().nonnegative(),
      high: z.number().int().nonnegative(),
      medium: z.number().int().nonnegative(),
      total: z.number().int().nonnegative()
    }),
    topFindings: z.array(
      z.object({
        ruleId: z.string().min(1),
        severity: z.enum(["critical", "high", "medium"]),
        title: z.string().min(1),
        message: z.string().min(1)
      })
    ),
    recommendedManifest: traceRootManifestSchema
  })
  .passthrough();

export type SavedHardeningProfile = z.infer<typeof hardeningProfileSchema>;

export interface HardeningProfileLoadResult {
  profile: SavedHardeningProfile | null;
  profilePath: string | null;
  error?: string;
}

const hardeningProfileName = "traceroot.hardened.profile.json";

function formatValidationError(error: ZodError): string {
  return error.issues
    .map((issue) => `${issue.path.join(".") || "root"}: ${issue.message}`)
    .join("; ");
}

export async function loadHardeningProfile(
  rootDir: string
): Promise<HardeningProfileLoadResult> {
  const absolutePath = path.join(rootDir, hardeningProfileName);

  try {
    await access(absolutePath);
  } catch {
    return {
      profile: null,
      profilePath: null
    };
  }

  try {
    const content = await readFile(absolutePath, "utf8");
    const rawValue = JSON.parse(content);
    const profile = hardeningProfileSchema.parse(rawValue);

    return {
      profile,
      profilePath: absolutePath
    };
  } catch (error) {
    if (error instanceof ZodError) {
      return {
        profile: null,
        profilePath: absolutePath,
        error: formatValidationError(error)
      };
    }

    return {
      profile: null,
      profilePath: absolutePath,
      error: error instanceof Error ? error.message : "Hardening profile could not be loaded."
    };
  }
}
