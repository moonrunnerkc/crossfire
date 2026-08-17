import { createHash } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import type { FuzzEngine as FuzzEngineId } from "../config/index.js";
import type { DetectorRun, Finding, Severity } from "../contracts/index.js";
import type { CrashReport } from "./crash-report.js";
import { resolveRepoFile, toPosix } from "./crash-report.js";
import { runTool } from "./exec.js";
import { fuzzFindingId } from "./identity.js";
import type { DetectorOutcome, FuzzEngine, FuzzJob } from "./types.js";

/** Where crash artifacts land inside the target repo, as a posix path. */
export const CRASH_ARTIFACT_DIR = ".crossfire/crashes";

/** Per input ceiling, the same one OSS-Fuzz uses, so a hang is a finding. */
export const INPUT_TIMEOUT_SECONDS = 25;

const MIN_RUN_MS = 1_000;
/** Backstop against a harness that crashes instantly forever. */
const MAX_RUNS = 32;
const DRY_RUNS_BEFORE_STOP = 2;
/** libFuzzer's crash minimizer, named so an engine can spot the invocation. */
export const MINIMIZE_CRASH_FLAG = "-minimize_crash=1";
const MINIMIZE_RUNS = 5_000;
const MINIMIZE_TIMEOUT_MS = 60_000;
const REPLAY_TIMEOUT_MS = 60_000;
/** libFuzzer honours -max_total_time itself; this only catches a wedged process. */
const KILL_GRACE_MS = 15_000;

/** A reproducible crash is serious until someone proves otherwise. */
const DEFAULT_CRASH_SEVERITY: Severity = "high";

export interface EngineCommand {
  file: string;
  args: string[];
}

/**
 * The engine specific half of an adapter for a fuzzer that speaks libFuzzer's
 * command line. Everything else about running a harness is the same whichever
 * one it is: restart until the budget runs out, deduplicate by crash signature,
 * minimize, and prove the artifact still reproduces before shipping it. That
 * half lives in `drive` below, and an engine supplies only what is its own.
 */
export interface LibFuzzerTarget {
  readonly id: FuzzEngineId;
  /** Why this harness cannot be run at all, or undefined when it can. */
  unrunnable(job: FuzzJob): string | undefined;
  /** Runs the harness with these libFuzzer flags over these corpus dirs or inputs. */
  command(job: FuzzJob, flags: readonly string[], inputs: readonly string[]): EngineCommand;
  parseReport(stderr: string): CrashReport | undefined;
  /** Crash kinds this engine reports that are not the default severity. */
  readonly severityByKind: Readonly<Record<string, Severity>>;
  /** Follows the repro convention: exit 0 for as long as the crash is live. */
  reproCommand(job: FuzzJob, artifactRel: string): string;
}

export function libFuzzerDriver(target: LibFuzzerTarget): FuzzEngine {
  return { id: target.id, fuzz: (job) => drive(target, job) };
}

async function drive(target: LibFuzzerTarget, job: FuzzJob): Promise<DetectorOutcome> {
  const startedAt = performance.now();
  const { harness, scope } = job;
  const elapsed = (): number => Math.round(performance.now() - startedAt);

  const failed = (note: string): DetectorOutcome => ({
    run: {
      detector: "fuzz",
      harness_id: harness.id,
      status: "error",
      duration_ms: elapsed(),
      findings_emitted: 0,
      note,
    },
    findings: [],
  });

  // The harness and its corpus are read and executed like any other path, so
  // they answer to the same exclusion set the agents do.
  for (const path of [harness.entryPoint, harness.corpusDir]) {
    const decision = scope.pathScope.check(path);
    if (!decision.allowed) {
      return failed(`harness ${harness.id} is out of scope: ${decision.reason}`);
    }
  }

  const blocked = target.unrunnable(job);
  if (blocked !== undefined) {
    return failed(blocked);
  }

  const workspace = mkdtempSync(join(tmpdir(), "crossfire-fuzz-"));
  try {
    // The seed corpus is copied rather than fuzzed in place: libFuzzer writes
    // newly interesting units into the corpus directory it is given, and the
    // target repo is not ours to grow.
    const corpusDir = join(workspace, "corpus");
    mkdirSync(corpusDir, { recursive: true });
    const seedCorpus = resolve(scope.repoPath, harness.corpusDir);
    if (existsSync(seedCorpus)) {
      cpSync(seedCorpus, corpusDir, { recursive: true });
    }

    const deadline = startedAt + job.timeBudgetMs;
    const findings = new Map<string, Finding>();
    // Tracked apart from findings: a crash that failed to produce a shippable
    // artifact must not be retried on every remaining restart.
    const seenSignatures = new Set<string>();
    const notes: string[] = [];
    let runIndex = 0;
    let runsWithoutNewCrash = 0;

    while (performance.now() + MIN_RUN_MS < deadline) {
      if (runIndex >= MAX_RUNS) {
        notes.push(`stopped at the ${MAX_RUNS} run cap with budget left`);
        break;
      }

      const runDir = join(workspace, `run-${runIndex}`);
      mkdirSync(runDir, { recursive: true });
      const remainingMs = deadline - performance.now();
      const command = target.command(
        job,
        [
          `-max_total_time=${Math.max(1, Math.floor(remainingMs / 1000))}`,
          `-artifact_prefix=${runDir}/`,
          `-seed=${job.seed + runIndex}`,
        ],
        [corpusDir],
      );
      const result = await runTool(command.file, command.args, {
        cwd: scope.repoPath,
        timeoutMs: remainingMs + KILL_GRACE_MS,
      });
      runIndex += 1;

      if (result.spawnError !== undefined) {
        return failed(result.spawnError);
      }
      if (result.timedOut) {
        notes.push(`${target.id} overran its budget and was killed`);
        break;
      }
      if (result.exitCode === 0) {
        break;
      }

      const artifact = newestFile(runDir);
      if (artifact === undefined) {
        return failed(
          `${target.id} exited ${result.exitCode} without a crash artifact: ${tail(result.stderr)}`,
        );
      }
      const report = target.parseReport(result.stderr);
      if (report === undefined) {
        return failed(`${target.id} crashed with an unreadable report: ${tail(result.stderr)}`);
      }

      // A crashing seed would abort every later run during corpus replay.
      dropCorpusUnitMatching(corpusDir, artifact);

      if (seenSignatures.has(report.signature)) {
        runsWithoutNewCrash += 1;
        if (runsWithoutNewCrash >= DRY_RUNS_BEFORE_STOP) {
          break;
        }
        continue;
      }
      seenSignatures.add(report.signature);
      runsWithoutNewCrash = 0;

      const emission = await emitCrash(target, job, runDir, artifact, report);
      if (emission.note !== undefined) {
        notes.push(emission.note);
      }
      if (emission.finding !== undefined) {
        findings.set(report.signature, emission.finding);
      }
    }

    if (runIndex === 0) {
      notes.push(`budget of ${job.timeBudgetMs}ms was too short to start the harness`);
    }

    const run: DetectorRun = {
      detector: "fuzz",
      harness_id: harness.id,
      status: "ok",
      duration_ms: elapsed(),
      findings_emitted: findings.size,
      ...(notes.length > 0 ? { note: notes.join("; ") } : {}),
    };
    return { run, findings: [...findings.values()] };
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

interface CrashEmission {
  finding?: Finding;
  note?: string;
}

/**
 * Minimizes the crashing input, then proves the artifact it is about to ship
 * still reproduces the same crash. A minimized input that reaches a different
 * bug is discarded in favour of the raw one: a smaller artifact is never worth
 * a repro that proves something else.
 */
async function emitCrash(
  target: LibFuzzerTarget,
  job: FuzzJob,
  runDir: string,
  rawArtifact: string,
  report: CrashReport,
): Promise<CrashEmission> {
  const { harness, scope } = job;

  if (!(await replaysWithSignature(target, job, rawArtifact, report.signature))) {
    return { note: `dropped a ${report.kind} that would not replay from its own artifact` };
  }

  const minimizedPath = join(runDir, "minimized");
  const minimize = target.command(
    job,
    [MINIMIZE_CRASH_FLAG, `-runs=${MINIMIZE_RUNS}`, `-exact_artifact_path=${minimizedPath}`],
    [rawArtifact],
  );
  const minimizeResult = await runTool(minimize.file, minimize.args, {
    cwd: scope.repoPath,
    timeoutMs: MINIMIZE_TIMEOUT_MS,
  });

  const minimized =
    !minimizeResult.timedOut &&
    existsSync(minimizedPath) &&
    (await replaysWithSignature(target, job, minimizedPath, report.signature));

  const id = fuzzFindingId(report.signature);
  const artifactRel = `${CRASH_ARTIFACT_DIR}/${harness.id}/${id}.min`;
  mkdirSync(join(scope.repoPath, CRASH_ARTIFACT_DIR, harness.id), { recursive: true });
  copyFileSync(minimized ? minimizedPath : rawArtifact, join(scope.repoPath, artifactRel));
  // The raw input is kept so a signature that deduplicates too aggressively is
  // still recoverable after the fact.
  copyFileSync(rawArtifact, join(scope.repoPath, `${CRASH_ARTIFACT_DIR}/${harness.id}/${id}.raw`));

  const location = locate(report, job);
  const finding: Finding = {
    id,
    source: "fuzzer",
    confirmation_state: "confirmed",
    severity: target.severityByKind[report.kind] ?? DEFAULT_CRASH_SEVERITY,
    class: report.kind,
    file: location.file,
    ...(location.line === undefined ? {} : { line: location.line }),
    description: `${report.kind} reproduced by the ${harness.id} harness. Crash stack: ${describeStack(report)}.`,
    repro_command: target.reproCommand(job, artifactRel),
    expected_secure_behavior: `the ${harness.id} harness returns normally for the recorded input instead of aborting with ${report.kind}.`,
    crash_artifact: artifactRel,
  };

  return {
    finding,
    ...(minimized ? {} : { note: `${id} ships its raw artifact, minimization did not hold up` }),
  };
}

async function replaysWithSignature(
  target: LibFuzzerTarget,
  job: FuzzJob,
  artifactPath: string,
  signature: string,
): Promise<boolean> {
  const command = target.command(job, [], [artifactPath]);
  const replay = await runTool(command.file, command.args, {
    cwd: job.scope.repoPath,
    timeoutMs: REPLAY_TIMEOUT_MS,
  });
  if (replay.timedOut || replay.exitCode === 0) {
    return false;
  }
  return target.parseReport(replay.stderr)?.signature === signature;
}

function describeStack(report: CrashReport): string {
  return report.frames
    .slice(0, 3)
    .map((frame) =>
      frame.file === undefined
        ? frame.functionName
        : `${frame.functionName} (${frame.file}${frame.line === undefined ? "" : `:${frame.line}`})`,
    )
    .join(" <- ");
}

function locate(report: CrashReport, job: FuzzJob): { file: string; line?: number } {
  for (const frame of report.frames) {
    if (frame.file === undefined) {
      continue;
    }
    const file = resolveRepoFile(frame.file, job.scope.repoPath, job.scope.inScopeDirs);
    if (file !== undefined) {
      return { file, ...(frame.line === undefined ? {} : { line: frame.line }) };
    }
  }
  // Nothing in the stack mapped into the repo, so the harness is the only
  // honest location left.
  return { file: toPosix(job.harness.entryPoint) };
}

function newestFile(dir: string): string | undefined {
  const files = readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => join(dir, entry.name));
  if (files.length === 0) {
    return undefined;
  }
  return files.reduce((newest, file) =>
    statSync(file).mtimeMs > statSync(newest).mtimeMs ? file : newest,
  );
}

function dropCorpusUnitMatching(corpusDir: string, artifactPath: string): void {
  const artifact = readFileSync(artifactPath);
  const target = createHash("sha256").update(artifact).digest("hex");

  for (const entry of readdirSync(corpusDir, { withFileTypes: true })) {
    if (!entry.isFile()) {
      continue;
    }
    const path = join(corpusDir, entry.name);
    // Size first: a corpus can hold thousands of units and this runs inside the
    // fuzz loop, so only same-sized candidates are worth hashing.
    if (statSync(path).size !== artifact.length) {
      continue;
    }
    if (createHash("sha256").update(readFileSync(path)).digest("hex") === target) {
      unlinkSync(path);
    }
  }
}

function tail(stderr: string): string {
  return stderr.trim().split("\n").slice(-3).join(" ").slice(0, 300);
}
