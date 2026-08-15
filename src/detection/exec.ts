import { execa } from "execa";

export interface ToolResult {
  /** null when the process never produced one: killed by a signal, or never ran. */
  exitCode: number | null;
  /** Set when a signal ended the process. A sanitizer abort lands here. */
  signal?: string;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Set only when the binary could not be spawned at all. */
  spawnError?: string;
  durationMs: number;
}

export interface RunToolOptions {
  cwd: string;
  timeoutMs: number;
  /** Sanitizer output and scanner JSON both run large; 64MB per stream. */
  maxBuffer?: number;
}

const DEFAULT_MAX_BUFFER = 64 * 1024 * 1024;

/**
 * Runs a detector binary and reports what happened instead of throwing. Callers
 * map the result onto a DetectorRun status, so a missing tool or a blown budget
 * is recorded rather than swallowed.
 */
export async function runTool(
  file: string,
  args: readonly string[],
  options: RunToolOptions,
): Promise<ToolResult> {
  const startedAt = performance.now();
  const result = await execa(file, args, {
    cwd: options.cwd,
    timeout: options.timeoutMs,
    maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
    reject: false,
    stripFinalNewline: false,
  });
  const durationMs = Math.round(performance.now() - startedAt);

  // A sanitizer aborts the process, so "no exit code" is the normal shape of a
  // crash. Only a process that never ran at all counts as a spawn failure.
  const killed = result.isTerminated === true;
  const spawnFailed = typeof result.exitCode !== "number" && !result.timedOut && !killed;

  return {
    exitCode: typeof result.exitCode === "number" ? result.exitCode : null,
    ...(typeof result.signal === "string" ? { signal: result.signal } : {}),
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
    timedOut: result.timedOut === true,
    ...(spawnFailed ? { spawnError: result.message } : {}),
    durationMs,
  };
}

/** Wraps a token so it survives the shell a repro command is executed by. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}
