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
  // Detached so the whole process group can be killed at the deadline. execa's
  // own timeout signals only the process it spawned, and a test command or a
  // repro that runs its work in a child leaves that child holding the pipes
  // open: measured at 5s of wall clock against a 250ms budget, which turns a
  // bounded gate into a wait with no ceiling.
  const subprocess = execa(file, args, {
    cwd: options.cwd,
    maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
    reject: false,
    stripFinalNewline: false,
    detached: true,
  });

  let timedOut = false;
  const deadline = setTimeout(() => {
    timedOut = true;
    killGroup(subprocess.pid);
  }, options.timeoutMs);

  const result = await subprocess.finally(() => {
    clearTimeout(deadline);
  });
  const durationMs = Math.round(performance.now() - startedAt);

  // A sanitizer aborts the process, so "no exit code" is the normal shape of a
  // crash. Only a process that never ran at all counts as a spawn failure.
  const killed = result.isTerminated === true;
  const spawnFailed = typeof result.exitCode !== "number" && !timedOut && !killed;

  return {
    exitCode: typeof result.exitCode === "number" ? result.exitCode : null,
    ...(typeof result.signal === "string" ? { signal: result.signal } : {}),
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
    timedOut,
    ...(spawnFailed ? { spawnError: result.message } : {}),
    durationMs,
  };
}

function killGroup(pid: number | undefined): void {
  if (pid === undefined) {
    return;
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    // The group exited between the deadline firing and the signal landing,
    // which is the state the kill was after anyway.
  }
}

/** Wraps a token so it survives the shell a repro command is executed by. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}
