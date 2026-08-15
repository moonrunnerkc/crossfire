import { z } from "zod";

import { SeveritySchema } from "./severity.js";

/**
 * What Grok returns for one confirmed crash. The repro command is a proposal:
 * the broker runs it before it replaces the detector's own, since a repro
 * nobody executed is a claim rather than a check.
 */
export const CrashAnalysisSchema = z.strictObject({
  finding_id: z.string().min(1),
  root_cause: z.string().min(1),
  severity: SeveritySchema,
  repro_command: z.string().min(1),
  expected_secure_behavior: z.string().min(1),
});

export type CrashAnalysis = z.infer<typeof CrashAnalysisSchema>;

/**
 * What Grok returns for one scanner candidate: a repro that promotes it, or a
 * dismissal with the reason. There is no third answer, and confirming still
 * costs a passing repro run by the broker.
 */
export const CandidateVerdictSchema = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("confirmed"),
    finding_id: z.string().min(1),
    severity: SeveritySchema,
    repro_command: z.string().min(1),
    expected_secure_behavior: z.string().min(1),
  }),
  z.strictObject({
    status: z.literal("dismissed"),
    finding_id: z.string().min(1),
    reason: z.string().min(1),
  }),
]);

export type CandidateVerdict = z.infer<typeof CandidateVerdictSchema>;
