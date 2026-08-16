import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterAll, describe, expect, test } from "vitest";

import { createClaudeAgent, createGrokAgent } from "../src/adapters/index.js";
import type { RunConfig } from "../src/config/index.js";
import { loadRunConfig } from "../src/config/index.js";
import type { AgentId } from "../src/contracts/index.js";
import { createPathScope, createPermissionPolicy } from "../src/policy/index.js";
import type { AgentHandle } from "../src/transport/index.js";
import type { AgentRunner, AgentTurn } from "../src/broker/index.js";
import { createAgentRunner, createDetectorRunner, runLoop } from "../src/broker/index.js";
import { verifyLedger } from "../src/ledger/index.js";

/**
 * Off by default: this spawns the real Claude and Grok, runs the real scanners
 * and fuzzer, and spends real tokens. Run it with
 *
 *   CROSSFIRE_INTEGRATION=1 npx vitest run test/integration.test.ts
 *
 * It needs semgrep, osv-scanner, a clang carrying the libFuzzer runtime, and
 * both agent CLIs logged in.
 */
const INTEGRATION = process.env.CROSSFIRE_INTEGRATION === "1";
const RUN_TIMEOUT_MS = 1_800_000;

const REPO_ROOT = resolve(import.meta.dirname, "..");
const FIXTURE = resolve(REPO_ROOT, "fixtures/vulnerable-repo");
const SAMPLE_CONFIG = resolve(REPO_ROOT, "crossfire.sample.json");

const workspaces: string[] = [];

afterAll(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

/** The target is a git repository of its own, so the run can commit into it. */
function makeTarget(): string {
  const workspace = mkdtempSync(join(tmpdir(), "crossfire-integration-"));
  workspaces.push(workspace);
  const target = join(workspace, "vulnerable-repo");
  cpSync(FIXTURE, target, {
    recursive: true,
    filter: (source) => !["build", ".crossfire", ".git"].includes(basename(source)),
  });

  const git = (args: string[]): void => {
    execFileSync("git", args, { cwd: target, stdio: "pipe" });
  };
  git(["init", "-q", "-b", "main"]);
  git(["add", "-A"]);
  git(["-c", "user.name=fixture", "-c", "user.email=fixture@invalid", "commit", "-qm", "the target as it arrived"]);
  return target;
}

function configFor(target: string): RunConfig {
  const base = loadRunConfig(SAMPLE_CONFIG);
  return {
    ...base,
    target: {
      ...base.target,
      repoPath: target,
      buildCommand: "./build.sh",
      testCommand: "./test.sh",
    },
    loop: { ...base.loop, iterationCap: 2, turnTimeoutMs: 600_000 },
    detectors: {
      ...base.detectors,
      fuzz: { ...base.detectors.fuzz, timeBudgetMs: 30_000 },
    },
  };
}

function policyFor(agent: AgentId, target: string, config: RunConfig) {
  return createPermissionPolicy(agent, createPathScope(target, config.target.excludedPaths));
}

function recording(runner: AgentRunner): AgentRunner & { turns: AgentTurn[] } {
  const turns: AgentTurn[] = [];
  return {
    turns,
    run(turn: AgentTurn): Promise<string> {
      turns.push(turn);
      return runner.run(turn);
    },
  };
}

describe.runIf(INTEGRATION)("the whole loop against the vulnerable fixture", () => {
  test(
    "detects the seeded crash and scanner finding, and closes the crash",
    async () => {
      const target = makeTarget();
      const config = configFor(target);
      const ledgerPath = join(mkdtempSync(join(tmpdir(), "crossfire-run-")), "ledger.jsonl");

      const handles: Partial<Record<AgentId, AgentHandle>> = {
        claude: await createClaudeAgent({
          cwd: target,
          policy: policyFor("claude", target, config),
        }),
        grok: await createGrokAgent({ cwd: target, policy: policyFor("grok", target, config) }),
      };
      const agents = recording(createAgentRunner(handles));

      let result;
      try {
        result = await runLoop({
          config,
          ledgerPath,
          detectors: createDetectorRunner(config, { refuzzBudgetMs: 20_000 }),
          agents,
        });
      } finally {
        await Promise.all(Object.values(handles).map((handle) => handle.close()));
      }

      // The detectors found both seeded bugs, deterministically and without a
      // model in the loop.
      const firstRound = result.entries[0];
      expect(firstRound).toBeDefined();
      // Round one carries more than one fuzz run: the detection pass and the
      // post-fix cross-check, which is expected to find nothing.
      const runsFrom = (detector: string) =>
        firstRound!.detector_runs.filter((run) => run.detector === detector);
      expect(runsFrom("semgrep")).toContainEqual(
        expect.objectContaining({ status: "ok", findings_emitted: expect.any(Number) }),
      );
      expect(runsFrom("semgrep").some((run) => run.findings_emitted >= 1)).toBe(true);
      expect(runsFrom("fuzz").some((run) => run.status === "ok" && run.findings_emitted >= 1)).toBe(
        true,
      );

      // Both were driven through the agents the router names: the candidate to
      // Grok for confirmation, the crash to Grok for analysis, the batch to
      // Claude for the fix.
      const subtasks = agents.turns.map((turn) => `${turn.subtask}:${turn.agent}`);
      expect(subtasks).toContain("candidate-confirmation:grok");
      expect(subtasks).toContain("crash-analysis:grok");
      expect(subtasks).toContain("fix:claude");

      // The crash closed, judged by the broker re-running its repro.
      const closedCrash = result.entries
        .flatMap((entry) => entry.verify_results)
        .find((verify) => verify.finding_id.startsWith("fuzz-") && verify.outcome === "closed");
      expect(closedCrash).toBeDefined();

      // One commit per round on top of the target as it arrived, and a ledger
      // that verifies end to end.
      expect(verifyLedger(ledgerPath)).toEqual({ ok: true, entries: result.entries.length });
      const commits = Number(
        execFileSync("git", ["rev-list", "--count", "HEAD"], {
          cwd: target,
          encoding: "utf8",
        }).trim(),
      );
      expect(commits).toBe(result.entries.length + 1);
      expect(result.rounds).toBeGreaterThanOrEqual(1);
    },
    RUN_TIMEOUT_MS,
  );
});
