import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, test } from "vitest";

import type { RunConfig } from "../src/config/index.js";
import { loadRunConfig, parseRunConfig } from "../src/config/index.js";
import { parseJazzerReport, runFuzzers, runTool } from "../src/detection/index.js";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const FIXTURE = resolve(REPO_ROOT, "fixtures/vulnerable-js-repo");
const SAMPLE_CONFIG = resolve(REPO_ROOT, "crossfire.js-sample.json");

const INSTALL_TIMEOUT_MS = 300_000;
const FUZZ_TEST_TIMEOUT_MS = 180_000;
const CRASH_BUDGET_MS = 20_000;
const CLEAN_BUDGET_MS = 8_000;

/**
 * The harness runs on the target's own Jazzer.js install, so a machine that
 * cannot reach the registry cannot run these at all, and they announce
 * themselves as skipped rather than failing on a toolchain that was never
 * there. The install runs while the file is collected rather than in a hook,
 * because collection is when runIf reads the result.
 */
function installFixture(): string | undefined {
  try {
    execFileSync("./build.sh", { cwd: FIXTURE, stdio: "pipe", timeout: INSTALL_TIMEOUT_MS });
    return undefined;
  } catch (error) {
    const reason = `${(error as Error).message}`.split("\n")[0];
    console.warn(`Jazzer.js integration tests skipped, the fixture did not install: ${reason}`);
    return reason;
  }
}

const installError = installFixture();

afterAll(() => {
  rmSync(join(FIXTURE, ".crossfire"), { recursive: true, force: true });
});

function fixtureInstalled(): boolean {
  return installError === undefined;
}

function fuzzConfig(entryPoint: string, timeBudgetMs: number): RunConfig {
  const base = loadRunConfig(SAMPLE_CONFIG);
  const harness = base.detectors.fuzz.harnesses[0]!;
  return {
    ...base,
    detectors: {
      ...base.detectors,
      fuzz: {
        ...base.detectors.fuzz,
        timeBudgetMs,
        harnesses: [{ ...harness, entryPoint }],
      },
    },
  };
}

const RANGE_ERROR_REPORT = `==60951== Uncaught Exception: RangeError: The value of "offset" is out of range. It must be >= 0 and <= 1. Received 2
    at boundsError (node:internal/buffer:92:9)
    at readUInt16BE (node:internal/buffer:338:5)
    at Buffer.readUInt16BE (node:internal/buffer:1012:50)
    at decodeFrame (/repo/src/decode-frame.js:35:23)
    at module.exports.fuzz (/repo/fuzz/decode-frame.fuzz.js:6:3)
Executed .crossfire/crashes/decode-frame/crash-01 in 0 ms
`;

describe("Jazzer.js crash report parsing", () => {
  test("names the crash after the class of error that escaped the harness", () => {
    const report = parseJazzerReport(RANGE_ERROR_REPORT);

    expect(report?.kind).toBe("rangeerror");
    expect(report?.frames[0]).toEqual({
      functionName: "decodeFrame",
      file: "/repo/src/decode-frame.js",
      line: 35,
    });
  });

  test("drops the Node internals the crash surfaced through", () => {
    const report = parseJazzerReport(RANGE_ERROR_REPORT);

    expect(report?.frames.map((frame) => frame.functionName)).toEqual([
      "decodeFrame",
      "module.exports.fuzz",
    ]);
  });

  test("the signature ignores line numbers so one bug stays one finding", () => {
    const shifted = RANGE_ERROR_REPORT.replaceAll("decode-frame.js:35", "decode-frame.js:41")
      .replaceAll("==60951==", "==417==")
      .replaceAll("<= 1. Received 2", "<= 7. Received 9");

    expect(parseJazzerReport(shifted)?.signature).toBe(
      parseJazzerReport(RANGE_ERROR_REPORT)?.signature,
    );
  });

  test("a different error class in the same function is a different signature", () => {
    const typeError = RANGE_ERROR_REPORT.replace("RangeError:", "TypeError:");

    expect(parseJazzerReport(typeError)?.signature).not.toBe(
      parseJazzerReport(RANGE_ERROR_REPORT)?.signature,
    );
  });

  test("a bug detector finding is named by the bug it detected", () => {
    const report = parseJazzerReport(
      `==60128== Command Injection\n    in execSync(): called with 'echo go'\n    at module.exports.fuzz (/repo/fuzz/exec.fuzz.cjs:6:11)\n`,
    );

    expect(report?.kind).toBe("command-injection");
    expect(report?.frames).toHaveLength(1);
  });

  test("reads libFuzzer's own failures back through Jazzer.js", () => {
    const timeout = `ALARM: working on the last Unit for 26 seconds\n==99887== ERROR: libFuzzer: timeout after 26 seconds\nSUMMARY: libFuzzer: timeout\n`;

    expect(parseJazzerReport(timeout)?.kind).toBe("timeout");
    expect(parseJazzerReport("==1== ERROR: libFuzzer: out-of-memory (malloc(4096))\n")?.kind).toBe(
      "out-of-memory",
    );
  });

  test("a thrown value that is not an Error still reports a crash", () => {
    const report = parseJazzerReport("==99847== Uncaught Exception: a bare string, not an Error\n");

    expect(report?.kind).toBe("uncaught-exception");
    expect(report?.frames).toEqual([]);
  });

  test("resolves the file URLs an ESM harness reports frames as", () => {
    const report = parseJazzerReport(
      `==99715== Uncaught Exception: Error: boom\n    at decodeFrame (file:///repo/src/decode.js:41:9)\n`,
    );

    expect(report?.frames[0]?.file).toBe("/repo/src/decode.js");
  });

  test("keeps reading past a native frame that carries no location", () => {
    const report = parseJazzerReport(
      `==1== Uncaught Exception: TypeError: fn is not a function\n    at Array.map (<anonymous>)\n    at parse (/repo/src/a.js:3:1)\n`,
    );

    expect(report?.frames).toEqual([
      { functionName: "Array.map" },
      { functionName: "parse", file: "/repo/src/a.js", line: 3 },
    ]);
  });

  test("a frame with no line number is reported without one", () => {
    const report = parseJazzerReport(
      `==1== Uncaught Exception: Error: boom\n    at fuzz (/repo/fuzz/a.cjs:0:3)\n`,
    );

    expect(report?.frames[0]).toEqual({ functionName: "fuzz", file: "/repo/fuzz/a.cjs" });
  });

  test("a stack that is all runtime is still signed over", () => {
    const report = parseJazzerReport(
      `==1== Uncaught Exception: Error: boom\n    at readUInt16BE (node:internal/buffer:338:5)\n`,
    );

    expect(report?.signature).toBe("error|readUInt16BE");
  });

  test("libFuzzer's own status lines are not crashes", () => {
    expect(parseJazzerReport("==1== libFuzzer: run interrupted; exiting\n")).toBeUndefined();
    expect(parseJazzerReport("Done 4096 runs in 2 second(s)\n")).toBeUndefined();
  });

  test("a target that prints its own pid prefixed line cannot name the bug class", () => {
    const forged = `==1== ${"whatever the target decided to print on stderr, at length".repeat(3)}\n`;

    expect(parseJazzerReport(forged)).toBeUndefined();
  });
});

describe("Jazzer.js engine against the fixture", () => {
  test.runIf(fixtureInstalled())(
    "discovers, minimizes and emits the seeded crash",
    async () => {
      const result = await runFuzzers(fuzzConfig("fuzz/decode-frame.fuzz.js", CRASH_BUDGET_MS));

      expect(result.runs).toHaveLength(1);
      expect(result.runs[0]).toMatchObject({
        detector: "fuzz",
        harness_id: "decode-frame",
        status: "ok",
        findings_emitted: 1,
      });

      expect(result.findings).toHaveLength(1);
      const finding = result.findings[0]!;
      expect(finding.source).toBe("fuzzer");
      expect(finding.confirmation_state).toBe("confirmed");
      expect(finding.class).toBe("rangeerror");
      expect(finding.severity).toBe("high");
      expect(finding.file).toBe("src/decode-frame.js");
      expect(finding.id).toMatch(/^fuzz-[0-9a-f]{12}$/);

      const artifact = finding.crash_artifact!;
      expect(artifact).toBe(`.crossfire/crashes/decode-frame/${finding.id}.min`);
      const minimized = join(FIXTURE, artifact);
      const raw = join(FIXTURE, `.crossfire/crashes/decode-frame/${finding.id}.raw`);
      expect(existsSync(minimized)).toBe(true);
      expect(existsSync(raw)).toBe(true);

      // The true minimum is 5 bytes: the 4 byte magic plus a length byte that
      // promises more payload than the frame carries.
      const minimizedSize = statSync(minimized).size;
      expect(minimizedSize).toBeLessThanOrEqual(statSync(raw).size);
      expect(minimizedSize).toBeGreaterThanOrEqual(5);
      expect(minimizedSize).toBeLessThanOrEqual(64);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test.runIf(fixtureInstalled())(
    "the emitted artifact replays through the repro command",
    async () => {
      const result = await runFuzzers(fuzzConfig("fuzz/decode-frame.fuzz.js", CRASH_BUDGET_MS));
      const finding = result.findings[0]!;

      const survived = await runTool("sh", ["-c", finding.repro_command], {
        cwd: FIXTURE,
        timeoutMs: 60_000,
      });
      // Exit 0 means reproduced, per the repro convention.
      expect(survived.exitCode).toBe(0);

      const fixedHarness = finding.repro_command.replace(
        "decode-frame.fuzz.js",
        "decode-frame-fixed.fuzz.js",
      );
      const closed = await runTool("sh", ["-c", fixedHarness], { cwd: FIXTURE, timeoutMs: 60_000 });
      expect(closed.exitCode).not.toBe(0);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test.runIf(fixtureInstalled())(
    "the fixed harness yields nothing within budget",
    async () => {
      const result = await runFuzzers(
        fuzzConfig("fuzz/decode-frame-fixed.fuzz.js", CLEAN_BUDGET_MS),
      );

      expect(result.runs[0]).toMatchObject({ status: "ok", findings_emitted: 0 });
      expect(result.findings).toEqual([]);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );
});

describe("routing a JavaScript harness to the Jazzer.js adapter", () => {
  function bareTarget(): string {
    const repo = mkdtempSync(join(tmpdir(), "crossfire-jazzer-"));
    mkdirSync(join(repo, "fuzz", "corpus", "parse"), { recursive: true });
    writeFileSync(join(repo, "fuzz", "parse.fuzz.cjs"), "module.exports.fuzz = () => {};\n");
    writeFileSync(join(repo, "fuzz", "corpus", "parse", "seed"), "hello");
    return repo;
  }

  function configFor(repo: string, entryPoint: string): RunConfig {
    return parseRunConfig(
      {
        task: "fuzz a JavaScript target",
        target: { repoPath: repo, inScopeDirs: ["fuzz"], testCommand: "npm test" },
        detectors: {
          semgrep: { enabled: false, ruleset: "p/default", timeBudgetMs: 1000 },
          osvScanner: { enabled: false, lockfiles: ["package-lock.json"], timeBudgetMs: 1000 },
          fuzz: {
            timeBudgetMs: 5000,
            harnesses: [
              {
                id: "parse",
                language: "javascript",
                engine: "jazzer.js",
                entryPoint,
                corpusDir: "fuzz/corpus/parse",
              },
            ],
          },
        },
      },
      "inline",
      repo,
    );
  }

  test("a target with no Jazzer.js installed is an error, not an empty pass", async () => {
    const result = await runFuzzers(configFor(bareTarget(), "fuzz/parse.fuzz.cjs"));

    expect(result.runs[0]?.status).toBe("error");
    expect(result.runs[0]?.note).toContain("node_modules/.bin/jazzer");
    expect(result.findings).toEqual([]);
  });

  test("a harness module that does not exist is an error, not an empty pass", async () => {
    const result = await runFuzzers(configFor(bareTarget(), "fuzz/missing.fuzz.cjs"));

    expect(result.runs[0]?.status).toBe("error");
    expect(result.runs[0]?.note).toContain("does not exist");
    expect(result.findings).toEqual([]);
  });
});
