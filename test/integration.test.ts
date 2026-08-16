import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterAll, describe, expect, test } from "vitest";

import { runCli } from "../src/cli.js";
import { verifyLedger } from "../src/ledger/index.js";

/**
 * Off by default: this spawns the real Claude and Grok, runs the real scanners
 * and fuzzer, and spends real tokens. Run it with
 *
 *   CROSSFIRE_INTEGRATION=1 npx vitest run test/integration.test.ts
 *
 * It needs semgrep, osv-scanner, a clang carrying the libFuzzer runtime, and
 * both agent CLIs logged in. It drives the CLI rather than the loop directly,
 * so what it proves is the shipped path.
 */
const INTEGRATION = process.env.CROSSFIRE_INTEGRATION === "1";
const RUN_TIMEOUT_MS = 1_800_000;

const REPO_ROOT = resolve(import.meta.dirname, "..");
const FIXTURE = resolve(REPO_ROOT, "fixtures/vulnerable-repo");

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
  git([
    "-c",
    "user.name=fixture",
    "-c",
    "user.email=fixture@invalid",
    "commit",
    "-qm",
    "the target as it arrived",
  ]);
  return target;
}

function writeConfig(target: string): string {
  const path = join(mkdtempSync(join(tmpdir(), "crossfire-integration-config-")), "crossfire.json");
  writeFileSync(
    path,
    JSON.stringify(
      {
        task: "Find and close memory safety bugs in the target's request parsing path",
        target: {
          repoPath: target,
          inScopeDirs: ["src"],
          buildCommand: "./build.sh",
          testCommand: "./test.sh",
        },
        loop: { iterationCap: 2, severityBar: "medium", turnTimeoutMs: 600_000 },
        detectors: {
          semgrep: { ruleset: ".semgrep/crossfire-c.yml", timeBudgetMs: 120_000 },
          osvScanner: { lockfiles: ["package-lock.json"], timeBudgetMs: 60_000 },
          fuzz: {
            timeBudgetMs: 30_000,
            harnesses: [
              {
                id: "parse-request",
                language: "c",
                engine: "libfuzzer",
                entryPoint: "build/parse-request-fuzzer",
                corpusDir: "fuzz/corpus/parse-request",
              },
            ],
          },
        },
      },
      null,
      2,
    ),
  );
  return path;
}

function jsonl(path: string): Record<string, unknown>[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe.runIf(INTEGRATION)("the CLI against the vulnerable fixture", () => {
  test(
    "detects the seeded crash and scanner finding, closes the crash, and leaves a verifiable run",
    async () => {
      const target = makeTarget();
      const runDir = join(mkdtempSync(join(tmpdir(), "crossfire-integration-run-")), "run");

      const code = await runCli(
        ["run", "--config", writeConfig(target), "--run-dir", runDir],
        // Forwarded as well as ignored: seven minutes of silence is not useful.
        (text) => void process.stdout.write(text),
      );
      // 0 when the round closed everything, 1 when the cap arrived first. Both
      // are real outcomes; what the gate asks about is the evidence below.
      expect([0, 1]).toContain(code);

      // The detectors found both seeded bugs, deterministically and with no
      // model in the loop.
      const events = jsonl(join(runDir, "run.jsonl"));
      const detected = events.filter((event) => event.type === "detected");
      const detectorRuns = detected.flatMap(
        (event) => event.runs as { detector: string; status: string; findings_emitted: number }[],
      );
      expect(
        detectorRuns.some((run) => run.detector === "semgrep" && run.findings_emitted >= 1),
      ).toBe(true);
      expect(
        detectorRuns.some(
          (run) => run.detector === "fuzz" && run.status === "ok" && run.findings_emitted >= 1,
        ),
      ).toBe(true);

      // Both were driven through the agents the router names.
      const turns = events
        .filter((event) => event.type === "turn")
        .map((event) => `${String(event.subtask)}:${String(event.agent)}`);
      expect(turns).toContain("candidate-confirmation:grok");
      expect(turns).toContain("crash-analysis:grok");
      expect(turns).toContain("fix:claude");

      // The crash closed, judged by the broker re-running its repro.
      const ledgerPath = join(runDir, "ledger.jsonl");
      const entries = jsonl(ledgerPath) as unknown as {
        round: number;
        verify_results: { finding_id: string; outcome: string }[];
      }[];
      const closedCrash = entries
        .flatMap((entry) => entry.verify_results)
        .find((verify) => verify.finding_id.startsWith("fuzz-") && verify.outcome === "closed");
      expect(closedCrash).toBeDefined();

      // The run left what a run is supposed to leave.
      expect(verifyLedger(ledgerPath)).toEqual({ ok: true, entries: entries.length });
      for (const agent of ["claude", "grok"]) {
        const transcript = join(runDir, "transcripts", `${agent}.jsonl`);
        expect(existsSync(transcript)).toBe(true);
        const methods = jsonl(transcript).map(
          (entry) => (entry.message as { method?: string } | undefined)?.method,
        );
        expect(methods).toContain("initialize");
        expect(methods).toContain("session/prompt");
      }

      const commits = Number(
        execFileSync("git", ["rev-list", "--count", "HEAD"], {
          cwd: target,
          encoding: "utf8",
        }).trim(),
      );
      expect(commits).toBe(entries.length + 1);
    },
    RUN_TIMEOUT_MS,
  );
});
