import type { RunConfig } from "../config/index.js";
import { runTool } from "../detection/index.js";

export const DEFAULT_BUILD_TIMEOUT_MS = 600_000;

export interface BuildOptions {
  timeoutMs?: number;
}

export interface BuildOutcome {
  status: "ok" | "failed" | "not-configured";
  durationMs: number;
  /** Why it failed, taken from the build's own output. */
  note?: string;
}

/**
 * Rebuilds the target. A compiled target's repro replays a binary, and the
 * fuzzer fuzzes one, so between a patch and the checks that judge it there has
 * to be a build: without one the round measures the previous binary and a real
 * fix reads as a failure, or worse, a fix that does not compile reads as a pass.
 */
export async function runBuild(
  config: RunConfig,
  options: BuildOptions = {},
): Promise<BuildOutcome> {
  const command = config.target.buildCommand;
  if (command === undefined) {
    return { status: "not-configured", durationMs: 0 };
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_BUILD_TIMEOUT_MS;
  const result = await runTool("sh", ["-c", command], {
    cwd: config.target.repoPath,
    timeoutMs,
  });

  if (result.timedOut) {
    return {
      status: "failed",
      durationMs: result.durationMs,
      note: `the build command timed out after ${timeoutMs}ms`,
    };
  }
  if (result.exitCode !== 0) {
    return {
      status: "failed",
      durationMs: result.durationMs,
      note: `the build command failed: ${tail(result.spawnError ?? result.stderr ?? "")}`,
    };
  }

  return { status: "ok", durationMs: result.durationMs };
}

function tail(output: string): string {
  const lines = output.trim().split("\n").filter((line) => line.trim().length > 0);
  return lines.slice(-3).join(" ").slice(0, 500);
}
