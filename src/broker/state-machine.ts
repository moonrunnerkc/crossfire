import type { RunConfig } from "../config/index.js";
import type {
  AgentId,
  Finding,
  FindingsBatch,
  FixReport,
  LedgerEntry,
  Severity,
  VerifyResult,
} from "../contracts/index.js";
import type { ColdHuntRaise } from "../contracts/index.js";
import {
  CandidateVerdictSchema,
  ColdHuntRaisesSchema,
  CrashAnalysisSchema,
  FindingSchema,
  FixPlanSchema,
  FixReportSchema,
  formatIssues,
  meetsSeverityBar,
} from "../contracts/index.js";
import type { DetectionResult } from "../detection/index.js";
import { huntFindingId } from "../detection/index.js";
import type { RefuzzOutcome } from "../gates/index.js";
import { runBuild, runTestGate, runTests, verifyFindings } from "../gates/index.js";
import { LedgerWriter, hashPayload } from "../ledger/index.js";
import type { SubtaskClass } from "../router/index.js";
import { routeSubtask } from "../router/index.js";
import { BrokerError } from "./errors.js";
import type { RunEvent, TerminationReason } from "./events.js";
import { assertGitRepo, commitRound, diffSince, headSha } from "./git.js";
import { parseAgentJson } from "./parse.js";
import {
  buildCandidateConfirmationPrompt,
  buildColdHuntPrompt,
  buildCrashAnalysisPrompt,
  buildFixPlanPrompt,
  buildFixPrompt,
} from "./prompts.js";

export interface AgentTurn {
  subtask: SubtaskClass;
  /** Decided by the router before the turn is built. A runner must not re-decide it. */
  agent: AgentId;
  prompt: string;
  /** Fires on the per turn deadline or a manual abort. */
  signal: AbortSignal;
}

export interface AgentRunner {
  /** Runs one stateless turn and returns the agent's answer as text. */
  run(turn: AgentTurn): Promise<string>;
}

export interface DetectorRunner {
  detect(round: number): Promise<DetectionResult>;
  refuzz(openFindingIds: readonly string[]): Promise<RefuzzOutcome>;
}

export interface RunOptions {
  config: RunConfig;
  /** Written outside the target: the ledger is a record of the run, not of the repo. */
  ledgerPath: string;
  detectors: DetectorRunner;
  agents: AgentRunner;
  /** Manual abort. Takes effect at the next phase boundary. */
  signal?: AbortSignal;
  /** Diagnostics only. A run with no listener behaves identically. */
  onEvent?: (event: RunEvent) => void;
}

export interface RunResult {
  reason: TerminationReason;
  /** Completed rounds, which is also the number of ledger entries written. */
  rounds: number;
  entries: LedgerEntry[];
  /** Findings still open when the run stopped: survived, inconclusive, or newly found. */
  openFindings: Finding[];
}

/** Internal marker: a manual abort is a termination reason, not a failure. */
class RunAborted extends Error {}

/**
 * The loop. Every decision it makes is made here, in code: what runs, in which
 * order, which agent gets a subtask, whether a finding is real, and when to
 * stop. Agents answer questions inside a round and never influence its shape.
 */
export async function runLoop(options: RunOptions): Promise<RunResult> {
  const { config, detectors, agents } = options;
  const runSignal = options.signal;
  const repoPath = config.target.repoPath;

  await assertGitRepo(repoPath);
  // Detection fuzzes and scans a built target, so the build comes before
  // anything measures it. A target that cannot build has nothing to say yet.
  const firstBuild = await runBuild(config);
  if (firstBuild.status === "failed") {
    throw new BrokerError(`the target does not build, so the run cannot start: ${firstBuild.note}`);
  }
  const ledger = new LedgerWriter(options.ledgerPath);
  const baseline = await runTests(config);
  const startSha = await headSha(repoPath);

  const entries: LedgerEntry[] = [];
  const analyzedCrashes = new Set<string>();
  let open: Finding[] = [];
  // Only the turn helper needs this, and threading a round through five call
  // sites to reach it would be worse than one variable the loop owns.
  let currentRound = 0;

  function emit(event: RunEvent): void {
    options.onEvent?.(event);
  }

  emit({
    type: "run-started",
    task: config.task,
    repo_path: repoPath,
    iteration_cap: config.loop.iterationCap,
    severity_bar: config.loop.severityBar,
    baseline,
  });

  function throwIfAborted(): void {
    if (runSignal?.aborted === true) {
      throw new RunAborted();
    }
  }

  function finish(reason: TerminationReason): RunResult {
    emit({ type: "terminated", reason, rounds: entries.length });
    return { reason, rounds: entries.length, entries, openFindings: open };
  }

  async function turn(subtask: SubtaskClass, prompt: string): Promise<string> {
    const agent = routeSubtask(subtask);
    const timeout = AbortSignal.timeout(config.loop.turnTimeoutMs);
    const signal = runSignal === undefined ? timeout : AbortSignal.any([timeout, runSignal]);

    const startedAt = performance.now();
    const running = agents.run({ subtask, agent, prompt, signal });
    // A turn that fails after the deadline already ended it has nothing left to
    // report, and must not surface as an unhandled rejection.
    void running.catch(() => undefined);

    const deadline = new Promise<never>((_, reject) => {
      signal.addEventListener(
        "abort",
        () => {
          reject(
            runSignal?.aborted === true
              ? new RunAborted()
              : new BrokerError(
                  `the ${subtask} turn timed out after ${config.loop.turnTimeoutMs}ms`,
                ),
          );
        },
        { once: true },
      );
    });

    const answer = await Promise.race([running, deadline]);
    emit({
      type: "turn",
      round: currentRound,
      subtask,
      agent,
      duration_ms: Math.round(performance.now() - startedAt),
    });
    return answer;
  }

  /**
   * Rule 4, applied to a proposal rather than to a finding: the broker runs the
   * command itself and believes the exit code.
   */
  async function reproduces(finding: Finding): Promise<boolean> {
    const [result] = await verifyFindings(config, [finding]);
    return result?.outcome === "survived";
  }

  async function confirmCandidate(candidate: Finding): Promise<Finding | undefined> {
    const text = await turn(
      "candidate-confirmation",
      buildCandidateConfirmationPrompt({ config, finding: candidate }),
    );
    const verdict = parseAgentJson(CandidateVerdictSchema, text, "candidate-confirmation");
    if (verdict.finding_id !== candidate.id) {
      throw new BrokerError(
        `the candidate-confirmation turn answered about ${verdict.finding_id}, not ${candidate.id}`,
      );
    }
    if (verdict.status === "dismissed") {
      emit({
        type: "candidate-verdict",
        round: currentRound,
        finding_id: candidate.id,
        confirmed: false,
        reason: verdict.reason,
      });
      return undefined;
    }

    const promoted: Finding = {
      ...candidate,
      confirmation_state: "confirmed",
      severity: verdict.severity,
      repro_command: verdict.repro_command,
      expected_secure_behavior: verdict.expected_secure_behavior,
    };
    // A verdict of confirmed is a claim until the repro backs it. Nothing enters
    // a fix round on a command that does not reproduce.
    const holds = await reproduces(promoted);
    emit({
      type: "candidate-verdict",
      round: currentRound,
      finding_id: candidate.id,
      confirmed: holds,
      ...(holds ? {} : { reason: "the repro the turn proposed did not reproduce" }),
    });
    return holds ? promoted : undefined;
  }

  async function analyzeCrash(crash: Finding): Promise<Finding> {
    const text = await turn("crash-analysis", buildCrashAnalysisPrompt({ config, finding: crash }));
    const analysis = parseAgentJson(CrashAnalysisSchema, text, "crash-analysis");
    if (analysis.finding_id !== crash.id) {
      throw new BrokerError(
        `the crash-analysis turn answered about ${analysis.finding_id}, not ${crash.id}`,
      );
    }

    const analyzed: Finding = {
      ...crash,
      // Recorded for the fix prompt only. The severity bar was already applied to
      // what the detector reported, so a model's reading of severity cannot pull
      // a finding out of the loop.
      severity: analysis.severity,
      description: `${crash.description} Root cause: ${analysis.root_cause}`,
      expected_secure_behavior: analysis.expected_secure_behavior,
    };

    const proposed: Finding = { ...analyzed, repro_command: analysis.repro_command };
    const adopted = await reproduces(proposed);
    emit({
      type: "analyzed",
      round: currentRound,
      finding_id: crash.id,
      severity: analysis.severity,
      adopted_repro: adopted,
    });
    return adopted ? proposed : analyzed;
  }

  /**
   * The supplemental pass, off unless the config turns it on. What it returns is
   * a list of candidates, which is the whole safeguard: a raise goes through the
   * same confirmation as a scanner's, so this pass can add work to a round but
   * can never be the thing that decides a bug is real.
   */
  async function coldHunt(known: readonly Finding[]): Promise<Finding[]> {
    const text = await turn("cold-hunt", buildColdHuntPrompt({ config, known }));
    const { raises } = parseAgentJson(ColdHuntRaisesSchema, text, "cold-hunt");
    return raises.map((raise) => raisedCandidate(raise));
  }

  /**
   * The planner slot, off unless the config turns it on. Its output reaches one
   * section of the fix prompt and nothing else: no routing, no ordering, no say
   * in whether the round or the run continues.
   */
  async function planFix(batch: FindingsBatch): Promise<string> {
    const text = await turn("fix-planning", buildFixPlanPrompt({ config, batch }));
    const plan = parseAgentJson(FixPlanSchema, text, "fix-planning");
    if (plan.round !== batch.round) {
      throw new BrokerError(
        `the fix-planning turn answered for round ${plan.round}, but round ${batch.round} is in progress`,
      );
    }
    emit({ type: "planned", round: batch.round, summary: plan.summary });
    return plan.summary;
  }

  async function fixBatch(batch: FindingsBatch): Promise<FixReport> {
    const diff = await diffSince(repoPath, startSha);
    const plan = config.supplemental.planner ? await planFix(batch) : undefined;
    const text = await turn(
      "fix",
      buildFixPrompt({
        config,
        batch,
        ...(diff === "" ? {} : { diff }),
        ...(plan === undefined ? {} : { plan }),
      }),
    );
    const report = parseAgentJson(FixReportSchema, text, "fix");

    if (report.round !== batch.round) {
      throw new BrokerError(
        `the fix report is for round ${report.round}, but round ${batch.round} is in progress`,
      );
    }
    if (report.agent !== routeSubtask("fix")) {
      throw new BrokerError(`the fix report came back signed by ${report.agent}`);
    }
    const inBatch = new Set(batch.findings.map((finding) => finding.id));
    for (const fix of report.fixes) {
      if (!inBatch.has(fix.finding_id)) {
        throw new BrokerError(
          `the fix report claims ${fix.finding_id}, which is not in round ${batch.round}'s batch`,
        );
      }
    }

    return report;
  }

  for (let round = 1; round <= config.loop.iterationCap; round += 1) {
    if (runSignal?.aborted === true) {
      return finish("aborted");
    }
    const startedAt = new Date().toISOString();
    currentRound = round;
    emit({ type: "round-started", round });

    try {
      const detection = await detectors.detect(round);
      const detectorRuns = [...detection.runs];
      emit({
        type: "detected",
        round,
        runs: detection.runs,
        findings: detection.findings,
        duplicates_dropped: detection.duplicatesDropped,
      });
      throwIfAborted();

      // Carried findings win over a fresh copy of themselves: they hold the
      // confirmed state and the repro that were established in an earlier round.
      const detected = merge(open, detection.findings);
      const raised = config.supplemental.coldHunt ? await coldHunt(detected) : [];
      if (raised.length > 0) {
        emit({ type: "raised", round, findings: raised });
      }
      throwIfAborted();
      const working = withinBar(merge(detected, raised), config.loop.severityBar);

      const confirmed: Finding[] = [];
      for (const finding of working) {
        if (finding.confirmation_state === "dismissed") {
          continue;
        }
        if (finding.confirmation_state === "confirmed") {
          confirmed.push(finding);
          continue;
        }
        const promoted = await confirmCandidate(finding);
        if (promoted !== undefined) {
          confirmed.push(promoted);
        }
      }
      throwIfAborted();

      const batchFindings: Finding[] = [];
      for (const finding of confirmed) {
        if (finding.source === "fuzzer" && !analyzedCrashes.has(finding.id)) {
          batchFindings.push(await analyzeCrash(finding));
          analyzedCrashes.add(finding.id);
          continue;
        }
        batchFindings.push(finding);
      }
      const batch: FindingsBatch = { round, findings: batchFindings };
      throwIfAborted();

      const fixReport = batchFindings.length === 0 ? undefined : await fixBatch(batch);
      if (fixReport !== undefined) {
        emit({ type: "fixed", round, report: fixReport });
      }
      throwIfAborted();

      // What the repros replay and what the cross-check fuzzes are artifacts of
      // the patched source, so the rebuild sits between the fix and every check
      // that judges it. A build that fails leaves nothing judgeable: the round's
      // findings are inconclusive rather than closed, which keeps them open.
      const build = fixReport === undefined ? undefined : await runBuild(config);
      if (build !== undefined && build.status !== "not-configured") {
        emit({
          type: "built",
          round,
          status: build.status,
          ...(build.note === undefined ? {} : { note: build.note }),
        });
      }
      const verifyResults =
        build?.status === "failed"
          ? batchFindings.map((finding) => unverifiable(finding, build.note))
          : await verifyFindings(config, batchFindings);
      const unresolved = batchFindings.filter(
        (_, index) => verifyResults[index]?.outcome !== "closed",
      );
      emit({ type: "verified", round, results: verifyResults });
      throwIfAborted();

      const gate = await runTestGate(config, baseline);
      emit({ type: "tested", round, result: gate.result, regressed: gate.regressed });

      // The cross-check exists to test a patched build, so it runs only when a
      // round patched something, and not when the round is already halting.
      let reopened: Finding[] = [];
      if (fixReport !== undefined && !gate.regressed) {
        const outcome = await detectors.refuzz(unresolved.map((finding) => finding.id));
        detectorRuns.push(...outcome.runs);
        reopened = outcome.newFindings;
        emit({ type: "refuzzed", round, runs: outcome.runs, new_findings: outcome.newFindings });
      }

      const gitSha = await commitRound(
        repoPath,
        `crossfire round ${round}: ${batchFindings.length} confirmed, ${batchFindings.length - unresolved.length} closed, tests ${gate.result.status}`,
      );
      const entry = ledger.append({
        round,
        started_at: startedAt,
        ended_at: new Date().toISOString(),
        detector_runs: detectorRuns,
        findings_hash: hashPayload(batch),
        fixes_hash: hashPayload(fixReport ?? { round, agent: routeSubtask("fix"), fixes: [] }),
        verify_results: verifyResults,
        test_result: gate.result,
        git_sha: gitSha,
      });
      entries.push(entry);
      emit({
        type: "round-committed",
        round,
        git_sha: gitSha,
        entry_hash: entry.entry_hash,
      });
      open = merge(unresolved, reopened);

      if (gate.regressed) {
        return finish("test-regression");
      }
      if (open.length === 0) {
        return finish("clean");
      }
    } catch (error) {
      if (error instanceof RunAborted) {
        return finish("aborted");
      }
      throw error;
    }
  }

  return finish("iteration-cap");
}

/**
 * Turns one raise into a candidate the loop can carry. The broker assigns the
 * id, so a hunt cannot name its own finding, and the result is put through the
 * finding schema, so a raise that points outside the repo is rejected here
 * rather than reaching a repro run.
 */
function raisedCandidate(raise: ColdHuntRaise): Finding {
  const candidate = {
    id: huntFindingId(raise.class, raise.file, raise.line),
    source: "cold-hunt",
    confirmation_state: "candidate",
    severity: raise.severity,
    class: raise.class,
    file: raise.file,
    ...(raise.line === undefined ? {} : { line: raise.line }),
    description: raise.description,
    // A raise arrives with no repro, and false reproduces nothing, which is the
    // honest placeholder until confirmation replaces it with a working command.
    repro_command: "false",
    expected_secure_behavior: raise.expected_secure_behavior,
  };

  const result = FindingSchema.safeParse(candidate);
  if (!result.success) {
    throw new BrokerError(
      `the cold-hunt turn raised something that is not a finding:\n${formatIssues(result.error.issues)}`,
    );
  }
  return result.data;
}

function unverifiable(finding: Finding, note: string | undefined): VerifyResult {
  return {
    finding_id: finding.id,
    outcome: "inconclusive",
    exit_code: null,
    duration_ms: 0,
    note: note ?? "the target did not build, so its repro could not be run",
  };
}

function merge(preferred: readonly Finding[], others: readonly Finding[]): Finding[] {
  const byId = new Map<string, Finding>();
  for (const finding of [...preferred, ...others]) {
    if (!byId.has(finding.id)) {
      byId.set(finding.id, finding);
    }
  }
  return [...byId.values()];
}

function withinBar(findings: readonly Finding[], bar: Severity): Finding[] {
  return findings.filter((finding) => meetsSeverityBar(finding.severity, bar));
}
