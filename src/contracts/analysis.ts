import { z } from "zod";

import { RoundSchema } from "./finding.js";
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

/** Bounded so a hunt that decided everything is suspicious cannot flood a round. */
export const COLD_HUNT_MAX_RAISES = 10;

/**
 * What the optional cold-hunt pass may return. A raise carries no repro, because
 * a raise is not a finding: it becomes a candidate, and a candidate buys its way
 * into a fix round with a repro the broker runs, exactly like a scanner's.
 */
export const ColdHuntRaiseSchema = z.strictObject({
  class: z.string().min(1),
  file: z.string().min(1),
  line: z.number().int().positive().optional(),
  severity: SeveritySchema,
  description: z.string().min(1),
  expected_secure_behavior: z.string().min(1),
});

export const ColdHuntRaisesSchema = z.strictObject({
  raises: z.array(ColdHuntRaiseSchema).max(COLD_HUNT_MAX_RAISES),
});

export type ColdHuntRaise = z.infer<typeof ColdHuntRaiseSchema>;
export type ColdHuntRaises = z.infer<typeof ColdHuntRaisesSchema>;

/** A fix prompt paragraph has no business being longer than this. */
export const FIX_PLAN_MAX_CHARS = 1_200;

/**
 * The planner slot's whole output: prose for one section of the fix prompt. It
 * names no next step and picks no order of work, and nothing but the prompt
 * builder ever reads it.
 */
export const FixPlanSchema = z.strictObject({
  round: RoundSchema,
  summary: z.string().min(1).max(FIX_PLAN_MAX_CHARS),
});

export type FixPlan = z.infer<typeof FixPlanSchema>;
