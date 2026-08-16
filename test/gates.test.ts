import { execFileSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { afterAll, describe, expect, test } from "vitest";

import type { RunConfig } from "../src/config/index.js";
import { loadRunConfig } from "../src/config/index.js";
import type { Finding, TestResult } from "../src/contracts/index.js";
import {
  refuzzCrossCheck,
  runBuild,
  runTestGate,
  runTests,
  verifyFindings,
} from "../src/gates/index.js";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const FIXTURE = resolve(REPO_ROOT, "fixtures/vulnerable-repo");
const SAMPLE_CONFIG = resolve(REPO_ROOT, "crossfire.sample.json");

/** Compiling the target and replaying a sanitized binary outrun vitest's default. */
const SUBPROCESS_TEST_TIMEOUT_MS = 60_000;
const FUZZ_TEST_TIMEOUT_MS = 180_000;
const REFUZZ_BUDGET_MS = 25_000;
const CLEAN_REFUZZ_BUDGET_MS = 12_000;

/**
 * These gates build, fuzz, and deliberately break their target, so they work on
 * a private copy of the fixture rather than the checked-in one other test files
 * share. The copy and the build happen at module scope because `test.runIf` is
 * evaluated while tests are being collected, before any hook has run.
 */
const workspace = mkdtempSync(join(tmpdir(), "crossfire-gates-"));
const target = join(workspace, "vulnerable-repo");
cpSync(FIXTURE, target, {
  recursive: true,
  filter: (source) => !["build", ".crossfire"].includes(basename(source)),
});

const buildError = buildHarnesses();

function buildHarnesses(): string | undefined {
  try {
    for (const mode of ["vulnerable", "fixed"]) {
      execFileSync("./build.sh", [mode], { cwd: target, stdio: "pipe" });
    }
    return undefined;
  } catch (error) {
    const message = `${(error as Error).message}`.split("\n")[0];
    console.warn(`gate tests that need the fuzz harness are skipped, it did not build: ${message}`);
    return message;
  }
}

function harnessBuilt(): boolean {
  return buildError === undefined;
}

afterAll(() => {
  rmSync(workspace, { recursive: true, force: true });
});

function baseConfig(repoPath: string): RunConfig {
  const base = loadRunConfig(SAMPLE_CONFIG);
  const target = { ...base.target, repoPath };
  // The sample builds its target; these gates supply their own build command
  // when they are testing one.
  delete target.buildCommand;
  return { ...base, target };
}

function buildableConfig(repoPath: string, buildCommand: string): RunConfig {
  const base = baseConfig(repoPath);
  return { ...base, target: { ...base.target, buildCommand } };
}

function fuzzConfig(entryPoint: string): RunConfig {
  const base = baseConfig(target);
  const harness = base.detectors.fuzz.harnesses[0]!;
  return {
    ...base,
    detectors: {
      ...base.detectors,
      fuzz: { ...base.detectors.fuzz, harnesses: [{ ...harness, entryPoint }] },
    },
  };
}

function confirmedFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "sast-0123456789ab",
    source: "sast",
    confirmation_state: "confirmed",
    severity: "high",
    class: "insecure-strcpy",
    file: "src/parse_request.c",
    description: "unbounded copy into a fixed size buffer",
    repro_command: "exit 0",
    expected_secure_behavior: "the copy is bounded by the size of the destination",
    ...overrides,
  };
}

/** The shape libFuzzer findings carry: replay the artifact, negate the abort. */
function replayFinding(harness: string, artifact: string): Finding {
  return confirmedFinding({
    id: "fuzz-0123456789ab",
    source: "fuzzer",
    class: "heap-buffer-overflow",
    crash_artifact: artifact,
    repro_command: `! './${harness}' -timeout=25 '${artifact}'`,
  });
}

function writeCrashArtifact(relativePath: string): void {
  const path = join(target, relativePath);
  mkdirSync(dirname(path), { recursive: true });
  // 64 path bytes into request.path, which is 32 bytes inside a 40 byte struct.
  writeFileSync(path, `GET /${"A".repeat(64)}`);
}

function scriptRepo(name: string, body: string): string {
  const repo = join(workspace, name);
  mkdirSync(repo, { recursive: true });
  writeScript(repo, body);
  return repo;
}

function writeScript(repo: string, body: string): void {
  const path = join(repo, "run-tests.sh");
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
}

function scriptConfig(repo: string): RunConfig {
  const base = baseConfig(repo);
  return { ...base, target: { ...base.target, testCommand: "./run-tests.sh" } };
}

describe("verify gate", () => {
  test("a repro that exits 0 marks the finding survived", async () => {
    const results = await verifyFindings(baseConfig(target), [
      confirmedFinding({ repro_command: "exit 0" }),
    ]);

    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      finding_id: "sast-0123456789ab",
      outcome: "survived",
      exit_code: 0,
    });
  });

  test("a repro that exits non-zero marks the finding closed", async () => {
    const results = await verifyFindings(baseConfig(target), [
      confirmedFinding({ repro_command: "exit 3" }),
    ]);

    expect(results[0]).toMatchObject({ outcome: "closed", exit_code: 3 });
  });

  test("findings come back in the order they were given", async () => {
    const results = await verifyFindings(baseConfig(target), [
      confirmedFinding({ id: "sast-aaaaaaaaaaaa", repro_command: "exit 1" }),
      confirmedFinding({ id: "sast-bbbbbbbbbbbb", repro_command: "exit 0" }),
    ]);

    expect(results.map((result) => result.finding_id)).toEqual([
      "sast-aaaaaaaaaaaa",
      "sast-bbbbbbbbbbbb",
    ]);
    expect(results.map((result) => result.outcome)).toEqual(["closed", "survived"]);
  });

  test("a repro that overruns its timeout is inconclusive, not a quiet pass", async () => {
    const results = await verifyFindings(
      baseConfig(target),
      [confirmedFinding({ repro_command: "sleep 5" })],
      { timeoutMs: 250 },
    );

    expect(results[0]?.outcome).toBe("inconclusive");
    expect(results[0]?.note).toContain("timed out");
  });

  test("a fuzzer finding whose crash artifact is gone is inconclusive, not closed", async () => {
    const results = await verifyFindings(baseConfig(target), [
      replayFinding("build/parse-request-fuzzer", ".crossfire/crashes/parse-request/absent.min"),
    ]);

    // The repro would have exited non-zero on the missing file and read as a
    // fix. A crash we can no longer replay is not evidence of anything.
    expect(results[0]?.outcome).toBe("inconclusive");
    expect(results[0]?.note).toContain("crash artifact");
  });

  test("a crash artifact under an excluded path is refused rather than replayed", async () => {
    writeCrashArtifact("secrets/leaked.min");

    const results = await verifyFindings(baseConfig(target), [
      replayFinding("build/parse-request-fuzzer", "secrets/leaked.min"),
    ]);

    expect(results[0]?.outcome).toBe("inconclusive");
    expect(results[0]?.note).toContain("excluded");
  });

  test.runIf(harnessBuilt())(
    "replaying the crash artifact through the vulnerable harness reports survived",
    async () => {
      const artifact = ".crossfire/crashes/parse-request/seeded.min";
      writeCrashArtifact(artifact);

      const results = await verifyFindings(baseConfig(target), [
        replayFinding("build/parse-request-fuzzer", artifact),
      ]);

      expect(results[0]).toMatchObject({ outcome: "survived", exit_code: 0 });
    },
    SUBPROCESS_TEST_TIMEOUT_MS,
  );

  test.runIf(harnessBuilt())(
    "the same artifact through the patched harness reports closed",
    async () => {
      const artifact = ".crossfire/crashes/parse-request/seeded.min";
      writeCrashArtifact(artifact);

      const results = await verifyFindings(baseConfig(target), [
        replayFinding("build/parse-request-fuzzer-fixed", artifact),
      ]);

      expect(results[0]?.outcome).toBe("closed");
      expect(results[0]?.exit_code).not.toBe(0);
    },
    SUBPROCESS_TEST_TIMEOUT_MS,
  );
});

describe("test gate", () => {
  test(
    "a green baseline passes the gate",
    async () => {
      const config = baseConfig(target);
      const baseline = await runTests(config);
      expect(baseline).toMatchObject({ status: "pass", command: "./test.sh", exit_code: 0 });

      const outcome = await runTestGate(config, baseline);

      expect(outcome.result.status).toBe("pass");
      expect(outcome.regressed).toBe(false);
    },
    SUBPROCESS_TEST_TIMEOUT_MS,
  );

  test("an injected test failure is a regression against a green baseline", async () => {
    const repo = scriptRepo("injected-failure", "exit 0");
    const config = scriptConfig(repo);
    const baseline = await runTests(config);
    expect(baseline.status).toBe("pass");

    writeScript(repo, "echo 'assertion failed' >&2\nexit 1");
    const outcome = await runTestGate(config, baseline);

    expect(outcome.result).toMatchObject({ status: "fail", exit_code: 1 });
    expect(outcome.regressed).toBe(true);
  });

  test("a test command that overruns its timeout fails closed", async () => {
    const config = scriptConfig(scriptRepo("slow-tests", "sleep 5"));
    const baseline: TestResult = {
      status: "pass",
      command: "./run-tests.sh",
      exit_code: 0,
      duration_ms: 10,
    };

    const outcome = await runTestGate(config, baseline, { timeoutMs: 250 });

    expect(outcome.result.status).toBe("fail");
    expect(outcome.result.note).toContain("timed out");
    expect(outcome.regressed).toBe(true);
  });

  test("a baseline that was already red is not reported as a new regression", async () => {
    const config = scriptConfig(scriptRepo("red-baseline", "exit 1"));
    const baseline = await runTests(config);
    expect(baseline.status).toBe("fail");

    const outcome = await runTestGate(config, baseline);

    expect(outcome.result.status).toBe("fail");
    expect(outcome.regressed).toBe(false);
    expect(outcome.note).toContain("baseline");
  });
});

describe("build step", () => {
  test("a target with no build command reports that it was not configured", async () => {
    const outcome = await runBuild(baseConfig(target));

    expect(outcome.status).toBe("not-configured");
  });

  test("a build command that succeeds reports ok", async () => {
    const config = buildableConfig(scriptRepo("buildable", "exit 0"), "./run-tests.sh");

    const outcome = await runBuild(config);

    expect(outcome.status).toBe("ok");
    expect(outcome.note).toBeUndefined();
  });

  test("a build command that fails reports why", async () => {
    const repo = scriptRepo("unbuildable", "echo 'parse_request.c:12: error: expected ;' >&2\nexit 2");
    const config = buildableConfig(repo, "./run-tests.sh");

    const outcome = await runBuild(config);

    expect(outcome.status).toBe("failed");
    expect(outcome.note).toContain("error: expected");
  });

  test("a build command that overruns its timeout fails rather than hanging the round", async () => {
    const config = buildableConfig(scriptRepo("slow-build", "sleep 5"), "./run-tests.sh");

    const outcome = await runBuild(config, { timeoutMs: 250 });

    expect(outcome.status).toBe("failed");
    expect(outcome.note).toContain("timed out");
  });
});

describe("re-fuzz cross-check", () => {
  test.runIf(harnessBuilt())(
    "a crash a fix reopened comes back as a new confirmed finding",
    async () => {
      // The round closed this crash, so nothing is open going into the next one
      // and the patched build is expected to be quiet. It is not.
      const outcome = await refuzzCrossCheck(fuzzConfig("build/parse-request-fuzzer"), [], {
        timeBudgetMs: REFUZZ_BUDGET_MS,
      });

      expect(outcome.newFindings).toHaveLength(1);
      expect(outcome.newFindings[0]).toMatchObject({
        source: "fuzzer",
        confirmation_state: "confirmed",
        class: "heap-buffer-overflow",
        file: "src/parse_request.c",
      });
      expect(outcome.newFindings[0]?.crash_artifact).toBeDefined();
      expect(outcome.runs[0]).toMatchObject({ detector: "fuzz", status: "ok" });
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test.runIf(harnessBuilt())(
    "a crash still open from this round is not news",
    async () => {
      const config = fuzzConfig("build/parse-request-fuzzer");
      const reopened = await refuzzCrossCheck(config, [], { timeBudgetMs: REFUZZ_BUDGET_MS });
      const openId = reopened.newFindings[0]!.id;

      const outcome = await refuzzCrossCheck(config, [openId], {
        timeBudgetMs: REFUZZ_BUDGET_MS,
      });

      expect(outcome.newFindings).toEqual([]);
      // The fuzzer still found it. The gate knows it is the bug already on the
      // books rather than a regression the fix introduced.
      expect(outcome.runs[0]?.findings_emitted).toBe(1);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test.runIf(harnessBuilt())(
    "the patched build turns up nothing new within its bounded budget",
    async () => {
      const outcome = await refuzzCrossCheck(fuzzConfig("build/parse-request-fuzzer-fixed"), [], {
        timeBudgetMs: CLEAN_REFUZZ_BUDGET_MS,
      });

      expect(outcome.newFindings).toEqual([]);
      expect(outcome.runs[0]).toMatchObject({ status: "ok", findings_emitted: 0 });
    },
    FUZZ_TEST_TIMEOUT_MS,
  );
});
