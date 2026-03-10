import { z } from "zod";

export const baselineEntrySchema = z.object({
  fingerprint: z.string().min(1),
  ruleId: z.string().min(1),
  severity: z.enum(["critical", "high", "medium"]),
  file: z.string().nullable(),
  line: z.number().int().positive().optional()
});

export const traceRootBaselineSchema = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.string().datetime(),
  target: z.string().min(1),
  fingerprints: z.array(baselineEntrySchema)
});

export type TraceRootBaseline = z.infer<typeof traceRootBaselineSchema>;
export type TraceRootBaselineEntry = z.infer<typeof baselineEntrySchema>;
