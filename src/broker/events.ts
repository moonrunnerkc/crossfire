import type {
  AgentId,
  DetectorRun,
  Finding,
  FixReport,
  Severity,
  TestResult,
  VerifyResult,
} from "../contracts/index.js";
import type { BuildOutcome } from "../gates/index.js";
import type { SubtaskClass } from "../router/index.js";

/** CLAUDE.md rule 3. There is no fifth reason, and none of them is a model's call. */
export const TERMINATION_REASONS = ["clean", "iteration-cap", "test-regression", "aborted"] as const;

export type TerminationReason = (typeof TERMINATION_REASONS)[number];

/**
 * What a run says about itself as it goes. This is diagnostics, not evidence:
 * the ledger is the record that has to hold up, and nothing here feeds back into
 * the loop. A run with no listener behaves exactly the same.
 */
export type RunEvent =
  | {
      type: "run-started";
      task: string;
      repo_path: string;
      iteration_cap: number;
      severity_bar: Severity;
      baseline: TestResult;
    }
  | { type: "round-started"; round: number }
  | {
      type: "detected";
      round: number;
      runs: DetectorRun[];
      findings: Finding[];
      duplicates_dropped: number;
    }
  | { type: "raised"; round: number; findings: Finding[] }
  | {
      type: "candidate-verdict";
      round: number;
      finding_id: string;
      confirmed: boolean;
      reason?: string;
    }
  | {
      type: "analyzed";
      round: number;
      finding_id: string;
      severity: Severity;
      /** Whether the proposed repro reproduced and replaced the detector's. */
      adopted_repro: boolean;
    }
  | { type: "turn"; round: number; subtask: SubtaskClass; agent: AgentId; duration_ms: number }
  | { type: "planned"; round: number; summary: string }
  | { type: "fixed"; round: number; report: FixReport }
  | { type: "built"; round: number; status: BuildOutcome["status"]; note?: string }
  | { type: "verified"; round: number; results: VerifyResult[] }
  | { type: "tested"; round: number; result: TestResult; regressed: boolean }
  | { type: "refuzzed"; round: number; runs: DetectorRun[]; new_findings: Finding[] }
  | { type: "rescanned"; round: number; runs: DetectorRun[]; findings: Finding[] }
  | { type: "round-committed"; round: number; git_sha: string; entry_hash: string }
  | { type: "terminated"; reason: TerminationReason; rounds: number };
