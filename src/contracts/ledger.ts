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
});

export const TestResultSchema = z.strictObject({
  status: z.enum(TEST_STATUSES),
  command: z.string().min(1),
  exit_code: z.number().int().nullable(),
  duration_ms: durationMs,
});

export const LedgerEntryBodySchema = z.strictObject({
  round: RoundSchema,
  started_at: z.iso.datetime(),
  ended_at: z.iso.datetime(),
  detector_runs: z.array(DetectorRunSchema),
  findings_hash: sha256Hex,
  fixes_hash: sha256Hex,
  verify_results: z.array(VerifyResultSchema),
  test_result: TestResultSchema,
  git_sha: gitSha,
});

export const LedgerEntrySchema = LedgerEntryBodySchema.extend({
  prev_hash: sha256Hex,
  entry_hash: sha256Hex,
});

export type DetectorRun = z.infer<typeof DetectorRunSchema>;
export type VerifyResult = z.infer<typeof VerifyResultSchema>;
export type TestResult = z.infer<typeof TestResultSchema>;
export type LedgerEntryBody = z.infer<typeof LedgerEntryBodySchema>;
export type LedgerEntry = z.infer<typeof LedgerEntrySchema>;
export type LinkedLedgerEntry = Omit<LedgerEntry, "entry_hash">;
