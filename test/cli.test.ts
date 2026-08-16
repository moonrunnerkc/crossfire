import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import { runCli } from "../src/cli.js";
import { verifyLedger } from "../src/ledger/index.js";

/**
 * Everything here runs with no scanners, no fuzzer, no compiler, and no models.
 * That is the point of --dry-run: the broker, the gates, git, and the ledger are
 * real, and only the detectors and the agents are stubs.
 */
function makeTarget(): string {
  const dir = mkdtempSync(join(tmpdir(), "crossfire-cli-target-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src/app.js"), "// the target under repair\n");
  writeFileSync(join(dir, "run-tests.sh"), "#!/bin/sh\nexit 0\n");
  execFileSync("chmod", ["755", join(dir, "run-tests.sh")]);

  const git = (args: string[]): void => {
    execFileSync("git", args, { cwd: dir, stdio: "pipe" });
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
  return dir;
}

function writeConfig(target: string): string {
  const dir = mkdtempSync(join(tmpdir(), "crossfire-cli-config-"));
  const path = join(dir, "crossfire.json");
  writeFileSync(
    path,
    JSON.stringify({
      task: "Exercise the loop without real tools",
      target: {
        repoPath: target,
        inScopeDirs: ["src"],
        testCommand: "./run-tests.sh",
      },
      loop: { iterationCap: 2, severityBar: "medium", turnTimeoutMs: 10_000 },
      detectors: {
        semgrep: { enabled: false, ruleset: "p/security-audit", timeBudgetMs: 1_000 },
        osvScanner: { enabled: false, lockfiles: ["package-lock.json"], timeBudgetMs: 1_000 },
        fuzz: { enabled: false, timeBudgetMs: 1_000, harnesses: [] },
      },
    }),
  );
  return path;
}

function runDir(): string {
  return join(mkdtempSync(join(tmpdir(), "crossfire-cli-run-")), "run");
}

interface CliResult {
  code: number;
  output: string;
}

async function cli(...argv: string[]): Promise<CliResult> {
  let output = "";
  const code = await runCli(argv, (text) => {
    output += text;
  });
  return { code, output };
}

function ledgerRounds(dir: string): number[] {
  return readFileSync(join(dir, "ledger.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => (JSON.parse(line) as { round: number }).round);
}

describe("crossfire run --dry-run", () => {
  test("drives a whole round with no detectors, no models, and no compiler", async () => {
    const dir = runDir();
    const config = writeConfig(makeTarget());

    const { code, output } = await cli("run", "--config", config, "--dry-run", "--run-dir", dir);

    expect(code).toBe(0);
    expect(output).toContain("clean");
    expect(ledgerRounds(dir)).toEqual([1]);
    expect(verifyLedger(join(dir, "ledger.jsonl"))).toEqual({ ok: true, entries: 1 });
  });

  test("leaves the run artifacts a run is supposed to leave", async () => {
    const dir = runDir();
    const config = writeConfig(makeTarget());

    await cli("run", "--config", config, "--dry-run", "--run-dir", dir);

    expect(existsSync(join(dir, "ledger.jsonl"))).toBe(true);
    expect(existsSync(join(dir, "run.jsonl"))).toBe(true);

    const events = readFileSync(join(dir, "run.jsonl"), "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as { type: string });
    expect(events[0]?.type).toBe("run-started");
    expect(events.map((event) => event.type)).toContain("detected");
    expect(events.map((event) => event.type)).toContain("verified");
    expect(events.at(-1)?.type).toBe("terminated");
  });

  test("commits one round to the target", async () => {
    const dir = runDir();
    const target = makeTarget();

    await cli("run", "--config", writeConfig(target), "--dry-run", "--run-dir", dir);

    const commits = execFileSync("git", ["rev-list", "--count", "HEAD"], {
      cwd: target,
      encoding: "utf8",
    }).trim();
    expect(commits).toBe("2");
  });
});

describe("crossfire resume", () => {
  test("continues a partial ledger in the same run directory", async () => {
    const dir = runDir();
    const config = writeConfig(makeTarget());
    await cli("run", "--config", config, "--dry-run", "--run-dir", dir);
    expect(ledgerRounds(dir)).toEqual([1]);

    const { code } = await cli("resume", "--config", config, "--dry-run", "--run-dir", dir);

    expect(code).toBe(0);
    expect(ledgerRounds(dir)).toEqual([1, 2]);
    expect(verifyLedger(join(dir, "ledger.jsonl"))).toEqual({ ok: true, entries: 2 });
  });

  test("refuses a run directory that has no ledger to continue", async () => {
    const { code, output } = await cli(
      "resume",
      "--config",
      writeConfig(makeTarget()),
      "--dry-run",
      "--run-dir",
      runDir(),
    );

    expect(code).toBe(2);
    expect(output).toContain("no ledger");
  });
});

describe("crossfire export", () => {
  test("prints a chain verified export of a run's ledger", async () => {
    const dir = runDir();
    await cli("run", "--config", writeConfig(makeTarget()), "--dry-run", "--run-dir", dir);

    const { code, output } = await cli("export", "--ledger", join(dir, "ledger.jsonl"));

    expect(code).toBe(0);
    const exported = JSON.parse(output) as {
      verification: { ok: boolean; entries: number };
      entries: { round: number }[];
    };
    expect(exported.verification).toEqual({ ok: true, entries: 1 });
    expect(exported.entries.map((entry) => entry.round)).toEqual([1]);
  });

  test("writes the export to a file when asked", async () => {
    const dir = runDir();
    await cli("run", "--config", writeConfig(makeTarget()), "--dry-run", "--run-dir", dir);
    const out = join(dir, "export.json");

    const { code } = await cli("export", "--ledger", join(dir, "ledger.jsonl"), "--out", out);

    expect(code).toBe(0);
    expect((JSON.parse(readFileSync(out, "utf8")) as { verification: { ok: boolean } }).verification.ok).toBe(
      true,
    );
  });

  test("a tampered ledger exports as unverified and exits non-zero", async () => {
    const dir = runDir();
    await cli("run", "--config", writeConfig(makeTarget()), "--dry-run", "--run-dir", dir);
    const path = join(dir, "ledger.jsonl");
    const forged = JSON.parse(readFileSync(path, "utf8").trim()) as Record<string, unknown>;
    forged.git_sha = "9".repeat(40);
    writeFileSync(path, `${JSON.stringify(forged)}\n`);

    const { code, output } = await cli("export", "--ledger", path);

    expect(code).toBe(1);
    expect(output).toContain('"ok": false');
  });
});

describe("crossfire usage", () => {
  test("an unknown command is rejected with the usage text", async () => {
    const { code, output } = await cli("hunt");

    expect(code).toBe(2);
    expect(output).toContain("crossfire run");
  });

  test("run without a config is rejected", async () => {
    const { code, output } = await cli("run");

    expect(code).toBe(2);
    expect(output).toContain("--config");
  });

  test("no command at all prints usage", async () => {
    const { code, output } = await cli();

    expect(code).toBe(2);
    expect(output).toContain("crossfire export");
  });
});
