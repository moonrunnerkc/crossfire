import type { RunConfig } from "../config/index.js";
import type {
  AgentId,
  Finding,
  FindingsBatch,
  FixReport,
  LedgerEntry,
  Severity,
} from "../contracts/index.js";
import {
  CandidateVerdictSchema,
  CrashAnalysisSchema,
  FixReportSchema,
  meetsSeverityBar,
} from "../contracts/index.js";
import type { DetectionResult } from "../detection/index.js";
import type { RefuzzOutcome } from "../gates/index.js";
import { runTestGate, runTests, verifyFindings } from "../gates/index.js";
import { LedgerWriter, hashPayload } from "../ledger/index.js";
import type { SubtaskClass } from "../router/index.js";
import { routeSubtask } from "../router/index.js";
import { BrokerError } from "./errors.js";
import { assertGitRepo, commitRound, diffSince, headSha } from "./git.js";
import { parseAgentJson } from "./parse.js";
import {
  buildCandidateConfirmationPrompt,
  buildCrashAnalysisPrompt,
  buildFixPrompt,
} from "./prompts.js";

/** CLAUDE.md rule 3. There is no fifth reason, and none of them is a model's call. */
export const TERMINATION_REASONS = ["clean", "iteration-cap", "test-regression", "aborted"] as const;

export type TerminationReason = (typeof TERMINATION_REASONS)[number];

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
  const ledger = new LedgerWriter(options.ledgerPath);
  const baseline = await runTests(config);
  const startSha = await headSha(repoPath);

  const entries: LedgerEntry[] = [];
  const analyzedCrashes = new Set<string>();
  let open: Finding[] = [];

  function throwIfAborted(): void {
    if (runSignal?.aborted === true) {
      throw new RunAborted();
    }
  }

  function finish(reason: TerminationReason): RunResult {
    return { reason, rounds: entries.length, entries, openFindings: open };
  }

  async function turn(subtask: SubtaskClass, prompt: string): Promise<string> {
    const agent = routeSubtask(subtask);
    const timeout = AbortSignal.timeout(config.loop.turnTimeoutMs);
    const signal = runSignal === undefined ? timeout : AbortSignal.any([timeout, runSignal]);

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

    return Promise.race([running, deadline]);
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
    return (await reproduces(promoted)) ? promoted : undefined;
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
    return (await reproduces(proposed)) ? proposed : analyzed;
  }

  async function fixBatch(batch: FindingsBatch): Promise<FixReport> {
    const diff = await diffSince(repoPath, startSha);
    const text = await turn(
      "fix",
      buildFixPrompt({ config, batch, ...(diff === "" ? {} : { diff }) }),
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

    try {
      const detection = await detectors.detect(round);
      const detectorRuns = [...detection.runs];
      throwIfAborted();

      // Carried findings win over a fresh copy of themselves: they hold the
      // confirmed state and the repro that were established in an earlier round.
      const working = withinBar(merge(open, detection.findings), config.loop.severityBar);

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
      throwIfAborted();

      const verifyResults = await verifyFindings(config, batchFindings);
      const unresolved = batchFindings.filter(
        (_, index) => verifyResults[index]?.outcome !== "closed",
      );
      throwIfAborted();

      const gate = await runTestGate(config, baseline);

      // The cross-check exists to test a patched build, so it runs only when a
      // round patched something, and not when the round is already halting.
      let reopened: Finding[] = [];
      if (fixReport !== undefined && !gate.regressed) {
        const outcome = await detectors.refuzz(unresolved.map((finding) => finding.id));
        detectorRuns.push(...outcome.runs);
        reopened = outcome.newFindings;
      }

      const gitSha = await commitRound(
        repoPath,
        `crossfire round ${round}: ${batchFindings.length} confirmed, ${batchFindings.length - unresolved.length} closed, tests ${gate.result.status}`,
      );
      entries.push(
        ledger.append({
          round,
          started_at: startedAt,
          ended_at: new Date().toISOString(),
          detector_runs: detectorRuns,
          findings_hash: hashPayload(batch),
          fixes_hash: hashPayload(fixReport ?? { round, agent: routeSubtask("fix"), fixes: [] }),
          verify_results: verifyResults,
          test_result: gate.result,
          git_sha: gitSha,
        }),
      );
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
