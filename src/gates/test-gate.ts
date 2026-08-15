import type { RunConfig } from "../config/index.js";
import type { TestResult } from "../contracts/index.js";
import type { ToolResult } from "../detection/index.js";
import { runTool } from "../detection/index.js";

/** A target's suite is allowed to be slow. It is not allowed to be unbounded. */
export const DEFAULT_TEST_TIMEOUT_MS = 600_000;

export interface TestGateOptions {
  timeoutMs?: number;
}

export interface TestGateOutcome {
  result: TestResult;
  /** True only when a suite that passed at baseline now fails: the halt signal. */
  regressed: boolean;
  /** One line of why, for the halt message and the run log. */
  note: string;
}

/**
 * Runs the target's own test command. Used both to capture the baseline before
 * the first round and, through the gate, after every fix round. A run that could
 * not finish is a failure, not a pass: a suite nobody watched complete says
 * nothing about whether the fixes broke it.
 */
export async function runTests(
  config: RunConfig,
  options: TestGateOptions = {},
): Promise<TestResult> {
  const command = config.target.testCommand;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TEST_TIMEOUT_MS;
  const result = await runTool("sh", ["-c", command], {
    cwd: config.target.repoPath,
    timeoutMs,
  });
  const note = failureNote(result, timeoutMs);

  return {
    status: result.exitCode === 0 ? "pass" : "fail",
    command,
    exit_code: result.exitCode,
    duration_ms: result.durationMs,
    ...(note === undefined ? {} : { note }),
  };
}

/**
 * Re-runs the suite and compares it to the captured baseline. A regression is a
 * hard halt: the broker stops the run rather than stacking more fixes on top of
 * a target the last round broke.
 */
export async function runTestGate(
  config: RunConfig,
  baseline: TestResult,
  options: TestGateOptions = {},
): Promise<TestGateOutcome> {
  const result = await runTests(config, options);
  return { result, ...verdict(baseline, result) };
}

function verdict(baseline: TestResult, result: TestResult): { regressed: boolean; note: string } {
  if (result.status === "pass") {
    return { regressed: false, note: "the target's tests pass" };
  }
  if (baseline.status !== "pass") {
    // Nothing to regress from. The failing suite still lands in the ledger; the
    // run just does not halt over a target that arrived broken.
    return {
      regressed: false,
      note: "the target's tests fail, as they already did at baseline",
    };
  }
  return {
    regressed: true,
    note: `the target's tests passed at baseline and now fail: ${result.note ?? `exit ${result.exit_code}`}`,
  };
}

function failureNote(result: ToolResult, timeoutMs: number): string | undefined {
  if (result.timedOut) {
    return `the test command timed out after ${timeoutMs}ms`;
  }
  if (result.spawnError !== undefined) {
    return `the test command could not be run: ${result.spawnError}`;
  }
  if (result.exitCode === null) {
    return `the test command was killed by ${result.signal ?? "a signal"}`;
  }
  return undefined;
}
