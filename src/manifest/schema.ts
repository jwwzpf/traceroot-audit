import { z } from "zod";

export const traceRootManifestSchema = z
  .object({
    name: z.string().min(1),
    version: z.string().min(1),
    author: z.string().min(1),
    source: z.string().url(),
    capabilities: z.array(z.string().min(1)).default([]),
    risk_level: z.enum(["low", "medium", "high", "critical"]),
    side_effects: z.boolean(),
    idempotency: z
      .enum(["idempotent", "non_idempotent", "unknown", "not_applicable"])
      .optional(),
    interrupt_support: z
      .enum(["supported", "unsupported", "unknown", "not_applicable"])
      .optional(),
    confirmation_required: z.boolean().optional(),
    safeguards: z.array(z.string().min(1)).optional()
  })
  .passthrough();

export type TraceRootManifest = z.infer<typeof traceRootManifestSchema>;
