import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";

import type { RunConfig } from "../src/config/index.js";
import { loadRunConfig } from "../src/config/index.js";
import type { Finding, LedgerEntry } from "../src/contracts/index.js";
import type { DetectionResult } from "../src/detection/index.js";
import type { RefuzzOutcome } from "../src/gates/index.js";
import type {
  AgentRunner,
  AgentTurn,
  DetectorRunner,
  RunEvent,
  RunResult,
} from "../src/broker/index.js";
import { BrokerError, runLoop } from "../src/broker/index.js";
import { verifyLedger } from "../src/ledger/index.js";
import type { SubtaskClass } from "../src/router/index.js";

const SAMPLE_CONFIG = resolve(import.meta.dirname, "..", "crossfire.sample.json");

/**
 * The target is a real git repository with two seeded markers and a real test
 * script. Detectors and agents are stubbed, per P14, but everything the broker
 * does mechanically (repro runs, the test gate, commits, the ledger) is real,
 * which is the half of the loop worth testing.
 */
const CRASH: Finding = {
  id: "fuzz-aaaaaaaaaaaa",
  source: "fuzzer",
  confirmation_state: "confirmed",
  severity: "high",
  class: "heap-buffer-overflow",
  file: "src/app.js",
  line: 1,
  description: "the request path is copied without a bound",
  repro_command: "grep -q VULNERABLE src/app.js",
  expected_secure_behavior: "the copy is bounded",
  crash_artifact: ".crossfire/crashes/fuzz-aaaaaaaaaaaa.min",
};

const ADJACENT_CRASH: Finding = {
  ...CRASH,
  id: "fuzz-cccccccccccc",
  description: "the same parser mishandles a second field",
  repro_command: "grep -q ADJACENT src/app.js",
  crash_artifact: ".crossfire/crashes/fuzz-cccccccccccc.min",
};

const CANDIDATE: Finding = {
  id: "sast-bbbbbbbbbbbb",
  source: "sast",
  confirmation_state: "candidate",
  severity: "high",
  class: "insecure-strcpy",
  file: "src/app.js",
  line: 2,
  description: "semgrep matched an unbounded copy",
  repro_command: "semgrep scan --config rules.yml src/app.js | grep -q insecure-strcpy",
  expected_secure_behavior: "the rule no longer matches",
};

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

function writeScript(path: string, body: string): void {
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
}

function makeTarget(): string {
  const dir = mkdtempSync(join(tmpdir(), "crossfire-target-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src/app.js"), "// VULNERABLE\n// ADJACENT\n");
  mkdirSync(join(dir, ".crossfire/crashes"), { recursive: true });
  for (const finding of [CRASH, ADJACENT_CRASH]) {
    writeFileSync(join(dir, finding.crash_artifact!), "crashing input");
  }
  writeScript(join(dir, "run-tests.sh"), "exit 0");

  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["add", "-A"]);
  git(dir, [
    "-c",
    "user.name=fixture",
    "-c",
    "user.email=fixture@invalid",
    "commit",
    "-qm",
    "seed the target",
  ]);
  return dir;
}

function ledgerPath(): string {
  return join(mkdtempSync(join(tmpdir(), "crossfire-run-")), "ledger.jsonl");
}

function configFor(
  repoPath: string,
  loop: Partial<RunConfig["loop"]> = {},
  buildCommand?: string,
): RunConfig {
  const base = loadRunConfig(SAMPLE_CONFIG);
  const target = { ...base.target, repoPath, inScopeDirs: ["src"], testCommand: "./run-tests.sh" };
  // The sample builds its own target; these rounds bring their own build script
  // only when the test is about one.
  delete target.buildCommand;
  return {
    ...base,
    target: {
      ...target,
      ...(buildCommand === undefined ? {} : { buildCommand }),
    },
    loop: { ...base.loop, iterationCap: 3, turnTimeoutMs: 10_000, ...loop },
  };
}

function coldHuntConfig(repoPath: string, loop: Partial<RunConfig["loop"]> = {}): RunConfig {
  const base = configFor(repoPath, loop);
  return { ...base, supplemental: { ...base.supplemental, coldHunt: true } };
}

function plannerConfig(repoPath: string, loop: Partial<RunConfig["loop"]> = {}): RunConfig {
  const base = configFor(repoPath, loop);
  return { ...base, supplemental: { ...base.supplemental, planner: true } };
}

function detection(findings: Finding[]): DetectionResult {
  return {
    runs: [
      {
        detector: "fuzz",
        harness_id: "stub",
        status: "ok",
        duration_ms: 5,
        findings_emitted: findings.length,
      },
    ],
    findings,
    duplicatesDropped: 0,
  };
}

function refuzzOutcome(newFindings: Finding[]): RefuzzOutcome {
  return {
    runs: [
      {
        detector: "fuzz",
        harness_id: "stub-refuzz",
        status: "ok",
        duration_ms: 3,
        findings_emitted: newFindings.length,
      },
    ],
    newFindings,
  };
}

/** Detection output per round, one entry per round, empty once it runs out. */
function stubDetectors(perRound: Finding[][], refuzzPerRound: Finding[][] = []): DetectorRunner {
  return {
    detect: (round) => Promise.resolve(detection(perRound[round - 1] ?? [])),
    refuzz: () => Promise.resolve(refuzzOutcome(refuzzPerRound.shift() ?? [])),
  };
}

type TurnHandler = (turn: AgentTurn) => string | Promise<string>;

function stubAgents(script: Partial<Record<SubtaskClass, TurnHandler>>): AgentRunner & {
  turns: AgentTurn[];
} {
  const turns: AgentTurn[] = [];
  return {
    turns,
    run(turn: AgentTurn): Promise<string> {
      turns.push(turn);
      const handler = script[turn.subtask];
      if (handler === undefined) {
        return Promise.reject(new Error(`the stub agent was asked for ${turn.subtask}`));
      }
      return Promise.resolve(handler(turn));
    },
  };
}

function roundOf(turn: AgentTurn): number {
  const match = /^Round: (\d+)$/m.exec(turn.prompt);
  if (match === null) {
    throw new Error("the fix prompt carries no round");
  }
  return Number(match[1]);
}

function analysisOf(finding: Finding): string {
  return JSON.stringify({
    finding_id: finding.id,
    root_cause: "the length is never checked against the destination",
    severity: finding.severity,
    repro_command: finding.repro_command,
    expected_secure_behavior: finding.expected_secure_behavior,
  });
}

function fixReportOf(turn: AgentTurn, findingIds: string[]): string {
  return JSON.stringify({
    round: roundOf(turn),
    agent: "claude",
    fixes: findingIds.map((finding_id) => ({
      finding_id,
      files_changed: ["src/app.js"],
      summary: "bounded the copy",
    })),
  });
}

/** What a real fix does: change the code so the repro stops reproducing. */
function removeMarker(repoPath: string, marker: string): void {
  const path = join(repoPath, "src/app.js");
  writeFileSync(path, readFileSync(path, "utf8").replace(marker, "FIXED"));
}

function commitCount(repoPath: string): number {
  return Number(git(repoPath, ["rev-list", "--count", "HEAD"]));
}

function entries(result: RunResult): LedgerEntry[] {
  return result.entries;
}

describe("termination on zero surviving findings", () => {
  test("a round whose fix closes every repro ends the run clean", async () => {
    const target = makeTarget();
    const path = ledgerPath();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: path,
      detectors: stubDetectors([[CRASH]]),
      agents,
    });

    expect(result.reason).toBe("clean");
    expect(result.rounds).toBe(1);
    expect(result.openFindings).toEqual([]);

    const [entry] = entries(result);
    expect(entry?.round).toBe(1);
    expect(entry?.verify_results).toEqual([
      { finding_id: CRASH.id, outcome: "closed", exit_code: 1, duration_ms: expect.any(Number) },
    ]);
    expect(entry?.test_result.status).toBe("pass");
    expect(verifyLedger(path)).toEqual({ ok: true, entries: 1 });
  });

  test("the round writes exactly one ledger entry and one commit", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]]),
      agents,
    });

    expect(commitCount(target)).toBe(2);
    expect(entries(result)).toHaveLength(1);
    expect(entries(result)[0]?.git_sha).toBe(git(target, ["rev-parse", "HEAD"]));
  });

  test("both detector passes of the round land in the ledger entry", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]]),
      agents,
    });

    expect(entries(result)[0]?.detector_runs.map((run) => run.harness_id)).toEqual([
      "stub",
      "stub-refuzz",
    ]);
  });

  test("each subtask goes to the agent the router names", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "candidate-confirmation": () =>
        JSON.stringify({
          status: "confirmed",
          finding_id: CANDIDATE.id,
          severity: "high",
          repro_command: "grep -q VULNERABLE src/app.js",
          expected_secure_behavior: "the copy is bounded",
        }),
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id, CANDIDATE.id]);
      },
    });

    await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH, CANDIDATE]]),
      agents,
    });

    expect(agents.turns.map((turn) => [turn.subtask, turn.agent])).toEqual([
      ["candidate-confirmation", "grok"],
      ["crash-analysis", "grok"],
      ["fix", "claude"],
    ]);
  });
});

describe("termination on the iteration cap", () => {
  test("a fix that changes nothing runs the loop to the cap", async () => {
    const target = makeTarget();
    const path = ledgerPath();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      // Claims a fix without touching the file. The repro is the only thing the
      // broker believes, so the finding survives every round.
      fix: (turn) => fixReportOf(turn, [CRASH.id]),
    });

    const result = await runLoop({
      config: configFor(target, { iterationCap: 2 }),
      ledgerPath: path,
      detectors: stubDetectors([[CRASH], [CRASH]]),
      agents,
    });

    expect(result.reason).toBe("iteration-cap");
    expect(result.rounds).toBe(2);
    expect(result.openFindings.map((finding) => finding.id)).toEqual([CRASH.id]);
    expect(entries(result).map((entry) => entry.round)).toEqual([1, 2]);
    expect(entries(result).map((entry) => entry.verify_results[0]?.outcome)).toEqual([
      "survived",
      "survived",
    ]);
    expect(commitCount(target)).toBe(3);
    expect(verifyLedger(path)).toEqual({ ok: true, entries: 2 });
  });

  test("a crash is analyzed once, not again every round it survives", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => fixReportOf(turn, [CRASH.id]),
    });

    await runLoop({
      config: configFor(target, { iterationCap: 3 }),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH], [CRASH], [CRASH]]),
      agents,
    });

    expect(agents.turns.filter((turn) => turn.subtask === "crash-analysis")).toHaveLength(1);
    expect(agents.turns.filter((turn) => turn.subtask === "fix")).toHaveLength(3);
  });
});

describe("halting on a test regression", () => {
  test("a fix that closes the finding but breaks the suite halts the run", async () => {
    const target = makeTarget();
    const path = ledgerPath();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        writeScript(join(target, "run-tests.sh"), "echo 'assertion failed' >&2\nexit 1");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target, { iterationCap: 5 }),
      ledgerPath: path,
      detectors: stubDetectors([[CRASH], [CRASH]]),
      agents,
    });

    expect(result.reason).toBe("test-regression");
    expect(result.rounds).toBe(1);
    expect(entries(result)).toHaveLength(1);
    expect(entries(result)[0]?.test_result).toMatchObject({
      status: "fail",
      command: "./run-tests.sh",
      exit_code: 1,
    });
    // The round finished, so it still leaves its receipt.
    expect(commitCount(target)).toBe(2);
    expect(verifyLedger(path)).toEqual({ ok: true, entries: 1 });
  });

  test("the regression halt beats the re-fuzz pass, which never runs", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        writeScript(join(target, "run-tests.sh"), "exit 1");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]], [[ADJACENT_CRASH]]),
      agents,
    });

    expect(result.reason).toBe("test-regression");
    expect(entries(result)[0]?.detector_runs.map((run) => run.harness_id)).toEqual(["stub"]);
  });
});

describe("termination on manual abort", () => {
  test("an abort between rounds keeps the rounds that finished", async () => {
    const target = makeTarget();
    const controller = new AbortController();
    const detectors = stubDetectors([[CRASH], [CRASH]]);
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        controller.abort();
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target, { iterationCap: 5 }),
      ledgerPath: ledgerPath(),
      detectors,
      agents,
      signal: controller.signal,
    });

    expect(result.reason).toBe("aborted");
    // The abort landed inside round 1, so round 1 never became a round.
    expect(entries(result)).toHaveLength(0);
    expect(commitCount(target)).toBe(1);
  });

  test("an abort before a round starts stops the loop with its entries intact", async () => {
    const target = makeTarget();
    const path = ledgerPath();
    const controller = new AbortController();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => fixReportOf(turn, [CRASH.id]),
    });

    const result = await runLoop({
      config: configFor(target, { iterationCap: 5 }),
      ledgerPath: path,
      detectors: {
        detect: (round) => {
          if (round === 2) {
            controller.abort();
          }
          return Promise.resolve(detection([CRASH]));
        },
        refuzz: () => Promise.resolve(refuzzOutcome([])),
      },
      agents,
      signal: controller.signal,
    });

    expect(result.reason).toBe("aborted");
    expect(result.rounds).toBe(1);
    expect(entries(result)).toHaveLength(1);
    expect(verifyLedger(path)).toEqual({ ok: true, entries: 1 });
  });
});

describe("the re-fuzz cross-check feeding the next round", () => {
  test("a crash the re-fuzz pass turned up is fixed in the next round", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": (turn) => analysisOf(turn.prompt.includes(CRASH.id) ? CRASH : ADJACENT_CRASH),
      fix: (turn) => {
        if (turn.prompt.includes(ADJACENT_CRASH.id)) {
          removeMarker(target, "ADJACENT");
          return fixReportOf(turn, [ADJACENT_CRASH.id]);
        }
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      // Round 1 detects the seeded crash and closes it; the re-fuzz pass on the
      // patched build turns up an adjacent one. Round 2 detects nothing new.
      detectors: stubDetectors([[CRASH], []], [[ADJACENT_CRASH], []]),
      agents,
    });

    expect(result.reason).toBe("clean");
    expect(result.rounds).toBe(2);
    const fixPrompts = agents.turns.filter((turn) => turn.subtask === "fix");
    expect(fixPrompts[1]?.prompt).toContain(ADJACENT_CRASH.id);
    expect(entries(result)[1]?.verify_results).toEqual([
      {
        finding_id: ADJACENT_CRASH.id,
        outcome: "closed",
        exit_code: 1,
        duration_ms: expect.any(Number),
      },
    ]);
  });
});

describe("a candidate cannot enter a fix round without a passing repro", () => {
  test("a confirmed verdict whose repro does not reproduce is dismissed", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "candidate-confirmation": () =>
        JSON.stringify({
          status: "confirmed",
          finding_id: CANDIDATE.id,
          severity: "high",
          // Exits non-zero, so it proves nothing, whatever the verdict says.
          repro_command: "grep -q NOT_IN_THIS_FILE src/app.js",
          expected_secure_behavior: "the copy is bounded",
        }),
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CANDIDATE]]),
      agents,
    });

    expect(result.reason).toBe("clean");
    expect(agents.turns.map((turn) => turn.subtask)).toEqual(["candidate-confirmation"]);
    expect(entries(result)[0]?.verify_results).toEqual([]);
  });

  test("a dismissed verdict drops the candidate", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "candidate-confirmation": () =>
        JSON.stringify({
          status: "dismissed",
          finding_id: CANDIDATE.id,
          reason: "the flagged path is unreachable from any entry point",
        }),
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CANDIDATE]]),
      agents,
    });

    expect(result.reason).toBe("clean");
    expect(agents.turns.filter((turn) => turn.subtask === "fix")).toHaveLength(0);
    expect(result.openFindings).toEqual([]);
  });

  test("a candidate with a repro that does reproduce enters the fix batch", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "candidate-confirmation": () =>
        JSON.stringify({
          status: "confirmed",
          finding_id: CANDIDATE.id,
          severity: "high",
          repro_command: "grep -q VULNERABLE src/app.js",
          expected_secure_behavior: "the copy is bounded",
        }),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CANDIDATE.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CANDIDATE]]),
      agents,
    });

    const fix = agents.turns.find((turn) => turn.subtask === "fix");
    expect(fix?.prompt).toContain(CANDIDATE.id);
    expect(fix?.prompt).toContain("grep -q VULNERABLE src/app.js");
    expect(entries(result)[0]?.verify_results[0]).toMatchObject({
      finding_id: CANDIDATE.id,
      outcome: "closed",
    });
  });
});

describe("rebuilding the target between the fix and the checks", () => {
  /** Fails only once the patch has landed, the way a fix that does not compile does. */
  function buildScript(repoPath: string): void {
    writeScript(join(repoPath, "build.sh"), "grep -q BROKEN src/app.js && exit 1\nexit 0");
  }

  test("a fix that does not build leaves its finding unverified, not closed", async () => {
    const target = makeTarget();
    buildScript(target);
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        // Closes the repro and breaks the build in the same edit. Without a
        // rebuild the stale binary would make this look like a clean fix.
        writeFileSync(join(target, "src/app.js"), "// BROKEN\n// ADJACENT\n");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target, { iterationCap: 1 }, "./build.sh"),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]]),
      agents,
    });

    expect(result.reason).toBe("iteration-cap");
    expect(entries(result)[0]?.verify_results[0]).toMatchObject({
      finding_id: CRASH.id,
      outcome: "inconclusive",
    });
    expect(entries(result)[0]?.verify_results[0]?.note).toContain("build");
    expect(result.openFindings.map((finding) => finding.id)).toEqual([CRASH.id]);
  });

  test("a target that cannot build at all is refused before the first round", async () => {
    const target = makeTarget();
    writeScript(join(target, "build.sh"), "echo 'no compiler here' >&2\nexit 1");

    await expect(
      runLoop({
        config: configFor(target, {}, "./build.sh"),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents: stubAgents({}),
      }),
    ).rejects.toThrow(/build/);
  });

  test("the rebuilt target is what verify and the re-fuzz pass see", async () => {
    const target = makeTarget();
    // Stands in for a compiler: the repro reads the built artifact, not the source.
    writeScript(join(target, "build.sh"), "cp src/app.js build.out");
    writeFileSync(join(target, "build.out"), "// VULNERABLE\n");
    const built: Finding = { ...CRASH, repro_command: "grep -q VULNERABLE build.out" };
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(built),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [built.id]);
      },
    });

    const result = await runLoop({
      config: configFor(target, {}, "./build.sh"),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[built]]),
      agents,
    });

    expect(result.reason).toBe("clean");
    expect(entries(result)[0]?.verify_results[0]?.outcome).toBe("closed");
  });
});

describe("the severity bar", () => {
  test("a finding below the bar never reaches an agent", async () => {
    const target = makeTarget();
    const agents = stubAgents({});

    const result = await runLoop({
      config: configFor(target, { severityBar: "high" }),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[{ ...CRASH, severity: "low" }]]),
      agents,
    });

    expect(result.reason).toBe("clean");
    expect(agents.turns).toEqual([]);
    expect(entries(result)[0]?.verify_results).toEqual([]);
  });
});

describe("resuming a partial ledger", () => {
  test("continues at the round after the last entry", async () => {
    const target = makeTarget();
    const path = ledgerPath();
    const first = await runLoop({
      config: configFor(target, { iterationCap: 1 }),
      ledgerPath: path,
      detectors: stubDetectors([[CRASH]]),
      agents: stubAgents({
        "crash-analysis": () => analysisOf(CRASH),
        fix: (turn) => fixReportOf(turn, [CRASH.id]),
      }),
    });
    expect(first.reason).toBe("iteration-cap");
    expect(entries(first).map((entry) => entry.round)).toEqual([1]);

    const resumed = await runLoop({
      config: configFor(target, { iterationCap: 3 }),
      ledgerPath: path,
      detectors: stubDetectors([[], [CRASH], []]),
      agents: stubAgents({
        "crash-analysis": () => analysisOf(CRASH),
        fix: (turn) => {
          removeMarker(target, "VULNERABLE");
          return fixReportOf(turn, [CRASH.id]);
        },
      }),
      resume: true,
    });

    expect(entries(resumed).map((entry) => entry.round)).toEqual([2]);
    expect(verifyLedger(path)).toEqual({ ok: true, entries: 2 });
  });

  test("a ledger already at the cap has no rounds left to run", async () => {
    const target = makeTarget();
    const path = ledgerPath();
    await runLoop({
      config: configFor(target, { iterationCap: 1 }),
      ledgerPath: path,
      detectors: stubDetectors([[]]),
      agents: stubAgents({}),
    });

    const resumed = await runLoop({
      config: configFor(target, { iterationCap: 1 }),
      ledgerPath: path,
      detectors: stubDetectors([[]]),
      agents: stubAgents({}),
      resume: true,
    });

    expect(resumed.reason).toBe("iteration-cap");
    expect(entries(resumed)).toEqual([]);
  });

  test("without resume a used ledger is refused rather than forked", async () => {
    const target = makeTarget();
    const path = ledgerPath();
    await runLoop({
      config: configFor(target, { iterationCap: 1 }),
      ledgerPath: path,
      detectors: stubDetectors([[]]),
      agents: stubAgents({}),
    });

    await expect(
      runLoop({
        config: configFor(target, { iterationCap: 2 }),
        ledgerPath: path,
        detectors: stubDetectors([[]]),
        agents: stubAgents({}),
      }),
    ).rejects.toThrow(/round 2/);
  });
});

describe("what a run reports as it goes", () => {
  test("emits an event for every phase of a round, in order", async () => {
    const target = makeTarget();
    const events: RunEvent[] = [];
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]]),
      agents,
      onEvent: (event) => events.push(event),
    });

    expect(events.map((event) => event.type)).toEqual([
      "run-started",
      "round-started",
      "detected",
      "turn",
      "analyzed",
      "turn",
      "fixed",
      "verified",
      "tested",
      "refuzzed",
      "round-committed",
      "terminated",
    ]);
  });

  test("the detector event carries what the detectors produced", async () => {
    const target = makeTarget();
    const events: RunEvent[] = [];
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => fixReportOf(turn, [CRASH.id]),
    });

    await runLoop({
      config: configFor(target, { iterationCap: 1 }),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]]),
      agents,
      onEvent: (event) => events.push(event),
    });

    const detected = events.find((event) => event.type === "detected");
    expect(detected).toMatchObject({ round: 1 });
    expect(detected?.type === "detected" && detected.findings.map((finding) => finding.id)).toEqual([
      CRASH.id,
    ]);
    expect(detected?.type === "detected" && detected.runs[0]?.detector).toBe("fuzz");

    const committed = events.find((event) => event.type === "round-committed");
    expect(committed?.type === "round-committed" && committed.git_sha).toMatch(/^[0-9a-f]{40}$/);
  });

  test("a candidate the broker refused says so in the log", async () => {
    const target = makeTarget();
    const events: RunEvent[] = [];
    const agents = stubAgents({
      "candidate-confirmation": () =>
        JSON.stringify({
          status: "dismissed",
          finding_id: CANDIDATE.id,
          reason: "the flagged path is unreachable",
        }),
    });

    await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CANDIDATE]]),
      agents,
      onEvent: (event) => events.push(event),
    });

    const verdict = events.find((event) => event.type === "candidate-verdict");
    expect(verdict).toMatchObject({
      finding_id: CANDIDATE.id,
      confirmed: false,
      reason: "the flagged path is unreachable",
    });
  });
});

describe("the cold hunt pass", () => {
  const RAISE = {
    class: "command-injection",
    file: "src/app.js",
    line: 2,
    severity: "high",
    description: "the request path reaches a shell without quoting",
    expected_secure_behavior: "the path is never interpolated into a shell command",
  };

  function raises(...found: unknown[]): string {
    return JSON.stringify({ raises: found });
  }

  test("does not run at all with the flag off", async () => {
    const target = makeTarget();
    const agents = stubAgents({});

    const result = await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[]]),
      agents,
    });

    expect(result.reason).toBe("clean");
    expect(agents.turns).toEqual([]);
  });

  test("a raise is a candidate that still has to buy its way in with a repro", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "cold-hunt": () => raises(RAISE),
      "candidate-confirmation": (turn) =>
        JSON.stringify({
          status: "confirmed",
          finding_id: /(hunt-[0-9a-f]{12})/.exec(turn.prompt)![1],
          severity: "high",
          repro_command: "grep -q VULNERABLE src/app.js",
          expected_secure_behavior: "the path is never interpolated into a shell command",
        }),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [/(hunt-[0-9a-f]{12})/.exec(turn.prompt)![1]!]);
      },
    });

    const result = await runLoop({
      config: coldHuntConfig(target),
      ledgerPath: ledgerPath(),
      // The detectors find nothing. Everything in this round came from the hunt.
      detectors: stubDetectors([[]]),
      agents,
    });

    expect(agents.turns.map((turn) => `${turn.subtask}:${turn.agent}`)).toEqual([
      "cold-hunt:grok",
      "candidate-confirmation:grok",
      "fix:claude",
    ]);
    expect(result.entries[0]?.verify_results[0]).toMatchObject({
      outcome: "closed",
    });
    expect(result.entries[0]?.verify_results[0]?.finding_id).toMatch(/^hunt-/);
  });

  test("a raise nobody can reproduce never reaches a fix round", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "cold-hunt": () => raises(RAISE),
      "candidate-confirmation": (turn) =>
        JSON.stringify({
          status: "confirmed",
          finding_id: /(hunt-[0-9a-f]{12})/.exec(turn.prompt)![1],
          severity: "high",
          repro_command: "grep -q NOT_IN_THIS_FILE src/app.js",
          expected_secure_behavior: "the path is never interpolated into a shell command",
        }),
    });

    const result = await runLoop({
      config: coldHuntConfig(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[]]),
      agents,
    });

    expect(agents.turns.filter((turn) => turn.subtask === "fix")).toHaveLength(0);
    expect(result.reason).toBe("clean");
    expect(result.entries[0]?.verify_results).toEqual([]);
  });

  test("the same raise in a later round is not hunted twice into the same round", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "cold-hunt": () => raises(RAISE),
      "candidate-confirmation": (turn) =>
        JSON.stringify({
          status: "confirmed",
          finding_id: /(hunt-[0-9a-f]{12})/.exec(turn.prompt)![1],
          severity: "high",
          repro_command: "grep -q VULNERABLE src/app.js",
          expected_secure_behavior: "the path is never interpolated into a shell command",
        }),
      // Claims the fix without making it, so the finding survives into round 2.
      fix: (turn) => fixReportOf(turn, [/(hunt-[0-9a-f]{12})/.exec(turn.prompt)![1]!]),
    });

    const result = await runLoop({
      config: coldHuntConfig(target, { iterationCap: 2 }),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[], []]),
      agents,
    });

    expect(result.reason).toBe("iteration-cap");
    // One finding across both rounds: the second hunt re-raises what is already
    // open and it collapses onto the same id rather than doubling.
    expect(result.openFindings).toHaveLength(1);
    expect(result.entries[1]?.verify_results).toHaveLength(1);
  });

  test("malformed raises halt the run like any other agent output", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "cold-hunt": () => JSON.stringify({ raises: [{ class: "", file: "src/app.js" }] }),
    });

    await expect(
      runLoop({
        config: coldHuntConfig(target),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[]]),
        agents,
      }),
    ).rejects.toThrow(/cold-hunt/);
  });
});

describe("the planner slot", () => {
  test("does not run at all with the flag off", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    await runLoop({
      config: configFor(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]]),
      agents,
    });

    expect(agents.turns.filter((turn) => turn.subtask === "fix-planning")).toHaveLength(0);
  });

  test("its summary reaches the fix prompt and nothing else", async () => {
    const target = makeTarget();
    const plainRun = await (async () => {
      const plain = makeTarget();
      const agents = stubAgents({
        "crash-analysis": () => analysisOf(CRASH),
        fix: (turn) => {
          removeMarker(plain, "VULNERABLE");
          return fixReportOf(turn, [CRASH.id]);
        },
      });
      return runLoop({
        config: configFor(plain),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      });
    })();

    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      "fix-planning": () =>
        JSON.stringify({ round: 1, summary: "One unbounded copy reached from the request line." }),
      fix: (turn) => {
        removeMarker(target, "VULNERABLE");
        return fixReportOf(turn, [CRASH.id]);
      },
    });

    const planned = await runLoop({
      config: plannerConfig(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[CRASH]]),
      agents,
    });

    // Control flow is untouched: same termination, same rounds, same verdicts.
    expect(planned.reason).toBe(plainRun.reason);
    expect(planned.rounds).toBe(plainRun.rounds);
    expect(planned.entries[0]?.verify_results).toEqual(plainRun.entries[0]?.verify_results);

    const fixTurn = agents.turns.find((turn) => turn.subtask === "fix");
    expect(fixTurn?.prompt).toContain("One unbounded copy reached from the request line.");
    expect(agents.turns.map((turn) => turn.subtask)).toEqual([
      "crash-analysis",
      "fix-planning",
      "fix",
    ]);
  });

  test("a summary that misses the schema halts rather than reaching the prompt", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      "fix-planning": () => JSON.stringify({ round: 1, summary: "" }),
      fix: (turn) => fixReportOf(turn, [CRASH.id]),
    });

    await expect(
      runLoop({
        config: plannerConfig(target),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      }),
    ).rejects.toThrow(/fix-planning/);
  });

  test("the planner never runs for a round with nothing to fix", async () => {
    const target = makeTarget();
    const agents = stubAgents({});

    await runLoop({
      config: plannerConfig(target),
      ledgerPath: ledgerPath(),
      detectors: stubDetectors([[]]),
      agents,
    });

    expect(agents.turns).toEqual([]);
  });
});

describe("failing closed on agent output", () => {
  test("output that is not JSON halts the run", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => "I had a look and it seems fine to me.",
    });

    await expect(
      runLoop({
        config: configFor(target),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      }),
    ).rejects.toThrow(BrokerError);
  });

  test("output that misses the schema halts the run", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => JSON.stringify({ finding_id: CRASH.id, root_cause: "" }),
    });

    await expect(
      runLoop({
        config: configFor(target),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      }),
    ).rejects.toThrow(/crash-analysis/);
  });

  test("an answer about a different finding halts the run", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf({ ...CRASH, id: "fuzz-999999999999" }),
    });

    await expect(
      runLoop({
        config: configFor(target),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      }),
    ).rejects.toThrow(/fuzz-999999999999/);
  });

  test("a fix report for the wrong round halts the run", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: () =>
        JSON.stringify({
          round: 7,
          agent: "claude",
          fixes: [{ finding_id: CRASH.id, files_changed: ["src/app.js"], summary: "done" }],
        }),
    });

    await expect(
      runLoop({
        config: configFor(target),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      }),
    ).rejects.toThrow(/round/);
  });

  test("a fix report claiming a finding that is not in the batch halts the run", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => analysisOf(CRASH),
      fix: (turn) => fixReportOf(turn, ["fuzz-not-in-the-batch"]),
    });

    await expect(
      runLoop({
        config: configFor(target),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      }),
    ).rejects.toThrow(/fuzz-not-in-the-batch/);
  });

  test("a turn that overruns the per turn timeout halts the run", async () => {
    const target = makeTarget();
    const agents = stubAgents({
      "crash-analysis": () => new Promise<string>(() => {}),
    });

    await expect(
      runLoop({
        config: configFor(target, { turnTimeoutMs: 150 }),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[CRASH]]),
        agents,
      }),
    ).rejects.toThrow(/timed out/);
  });

  test("a target that is not a git repository is refused before anything runs", async () => {
    const notARepo = mkdtempSync(join(tmpdir(), "crossfire-plain-"));
    writeScript(join(notARepo, "run-tests.sh"), "exit 0");

    await expect(
      runLoop({
        config: configFor(notARepo),
        ledgerPath: ledgerPath(),
        detectors: stubDetectors([[]]),
        agents: stubAgents({}),
      }),
    ).rejects.toThrow(/git repository/);
  });
});
