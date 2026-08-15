import { existsSync } from "node:fs";
import { join } from "node:path";

import type { RunConfig } from "../config/index.js";
import type { Finding, VerifyResult } from "../contracts/index.js";
import { runTool } from "../detection/index.js";
import type { PathScope } from "../policy/index.js";
import { createPathScope } from "../policy/index.js";

/** A repro drives one input through one entry point, not a fuzzing session. */
export const DEFAULT_REPRO_TIMEOUT_MS = 120_000;

export interface VerifyOptions {
  timeoutMs?: number;
}

/**
 * The only thing in the system that decides whether a fix worked. Each finding's
 * repro is run in the target repo and read against the convention: exit 0 means
 * the finding survived, non-zero means it is closed. A repro that could not be
 * run to completion is inconclusive, never a pass, because the failure modes of
 * a broken repro (missing artifact, killed process, blown timeout) all produce
 * the same non-zero exit a real fix does.
 */
export async function verifyFindings(
  config: RunConfig,
  findings: readonly Finding[],
  options: VerifyOptions = {},
): Promise<VerifyResult[]> {
  const scope = createPathScope(config.target.repoPath, config.target.excludedPaths);
  const timeoutMs = options.timeoutMs ?? DEFAULT_REPRO_TIMEOUT_MS;
  const results: VerifyResult[] = [];

  // Sequential: repros run sanitized binaries and whole test harnesses, and the
  // ledger records them in the order the broker handed them over.
  for (const finding of findings) {
    results.push(await verifyOne(finding, scope, timeoutMs));
  }

  return results;
}

async function verifyOne(
  finding: Finding,
  scope: PathScope,
  timeoutMs: number,
): Promise<VerifyResult> {
  const unusable = artifactProblem(finding, scope);
  if (unusable !== undefined) {
    return {
      finding_id: finding.id,
      outcome: "inconclusive",
      exit_code: null,
      duration_ms: 0,
      note: unusable,
    };
  }

  const result = await runTool("sh", ["-c", finding.repro_command], {
    cwd: scope.repoPath,
    timeoutMs,
  });
  const inconclusive = (note: string): VerifyResult => ({
    finding_id: finding.id,
    outcome: "inconclusive",
    exit_code: result.exitCode,
    duration_ms: result.durationMs,
    note,
  });

  if (result.timedOut) {
    return inconclusive(`the repro timed out after ${timeoutMs}ms`);
  }
  if (result.spawnError !== undefined) {
    return inconclusive(`the repro could not be run: ${result.spawnError}`);
  }
  if (result.exitCode === null) {
    return inconclusive(`the repro was killed by ${result.signal ?? "a signal"} before it reported`);
  }

  return {
    finding_id: finding.id,
    outcome: result.exitCode === 0 ? "survived" : "closed",
    exit_code: result.exitCode,
    duration_ms: result.durationMs,
  };
}

/**
 * A fuzzer finding is only verifiable while its minimized input is still on disk
 * and still readable under the exclusion set. Replaying without it exits
 * non-zero for the wrong reason, which reads exactly like a fix.
 */
function artifactProblem(finding: Finding, scope: PathScope): string | undefined {
  const artifact = finding.crash_artifact;
  if (artifact === undefined) {
    return undefined;
  }

  const decision = scope.check(artifact);
  if (!decision.allowed) {
    return `the crash artifact cannot be replayed: ${decision.reason}`;
  }
  if (!existsSync(join(scope.repoPath, artifact))) {
    return `the crash artifact ${artifact} is missing, so the repro proves nothing`;
  }

  return undefined;
}
