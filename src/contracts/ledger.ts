import { z } from "zod";

import { RoundSchema } from "./finding.js";

export const DETECTOR_IDS = ["semgrep", "osv-scanner", "fuzz"] as const;
export const DETECTOR_RUN_STATUSES = ["ok", "error", "timeout", "skipped"] as const;
export const VERIFY_OUTCOMES = ["survived", "closed", "inconclusive"] as const;
export const TEST_STATUSES = ["pass", "fail", "skipped"] as const;

const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/, "expected a sha256 hex digest");
const gitSha = z.string().regex(/^[0-9a-f]{40}$/, "expected a 40 character git sha");
const durationMs = z.number().int().nonnegative();

export const DetectorRunSchema = z.strictObject({
  detector: z.enum(DETECTOR_IDS),
  harness_id: z.string().min(1).optional(),
  status: z.enum(DETECTOR_RUN_STATUSES),
  duration_ms: durationMs,
  findings_emitted: z.number().int().nonnegative(),
  note: z.string().min(1).optional(),
});

export const VerifyResultSchema = z.strictObject({
  finding_id: z.string().min(1),
  outcome: z.enum(VERIFY_OUTCOMES),
  exit_code: z.number().int().nullable(),
  duration_ms: durationMs,
  /** Why an outcome is inconclusive. An unexplained one is unauditable. */
  note: z.string().min(1).optional(),
});

export const TestResultSchema = z.strictObject({
  status: z.enum(TEST_STATUSES),
  command: z.string().min(1),
  exit_code: z.number().int().nullable(),
  duration_ms: durationMs,
  /** Why the suite failed when the exit code alone does not say, for example a timeout. */
  note: z.string().min(1).optional(),
});

/**
 * A verdict a round reached about a finding, carried forward so the next round does not buy
 * it again. Keyed by the finding id, which already hashes the rule, the file and the
 * normalized construct, so a verdict cannot transfer across an edit to the thing it judged.
 *
 * A dismissal is an argument and expires; a closure is a repro and is re-run instead, which
 * is why the command travels with it. That asymmetry is the honest one: a mechanical check
 * can be trusted indefinitely, an argument cannot.
 */
export const FindingVerdictSchema = z.strictObject({
  finding_id: z.string().min(1),
  verdict: z.enum(["dismissed", "closed"]),
  /** Present for a closure, so a later round can re-run it rather than re-confirm it. */
  repro_command: z.string().min(1).optional(),
  /** The round that reached it, so a dismissal can be aged out. */
  decided_in_round: RoundSchema,
});

export const LedgerEntryBodySchema = z.strictObject({
  round: RoundSchema,
  started_at: z.iso.datetime(),
  ended_at: z.iso.datetime(),
  detector_runs: z.array(DetectorRunSchema),
  findings_hash: sha256Hex,
  fixes_hash: sha256Hex,
  verify_results: z.array(VerifyResultSchema),
  /** What this round decided about findings, for the rounds and runs after it. */
  verdicts: z.array(FindingVerdictSchema).default([]),
  test_result: TestResultSchema,
  git_sha: gitSha,
});

export const LedgerEntrySchema = LedgerEntryBodySchema.extend({
  prev_hash: sha256Hex,
  entry_hash: sha256Hex,
});

export type DetectorRun = z.infer<typeof DetectorRunSchema>;
export type VerifyResult = z.infer<typeof VerifyResultSchema>;
export type FindingVerdict = z.infer<typeof FindingVerdictSchema>;
export type TestResult = z.infer<typeof TestResultSchema>;
export type LedgerEntryBody = z.infer<typeof LedgerEntryBodySchema>;
export type LedgerEntry = z.infer<typeof LedgerEntrySchema>;
export type LinkedLedgerEntry = Omit<LedgerEntry, "entry_hash">;
