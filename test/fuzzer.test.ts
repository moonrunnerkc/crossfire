import { execFileSync } from "node:child_process";
import { existsSync, rmSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, test } from "vitest";

import type { RunConfig } from "../src/config/index.js";
import { loadRunConfig } from "../src/config/index.js";
import { parseCrashReport, resolveRepoFile, runFuzzers, runTool } from "../src/detection/index.js";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const FIXTURE = resolve(REPO_ROOT, "fixtures/vulnerable-repo");
const SAMPLE_CONFIG = resolve(REPO_ROOT, "crossfire.sample.json");

const BUILD_TIMEOUT_MS = 120_000;
const FUZZ_TEST_TIMEOUT_MS = 180_000;
const CRASH_BUDGET_MS = 25_000;
const CLEAN_BUDGET_MS = 12_000;

/**
 * The harness needs a clang carrying the libFuzzer runtime. Apple's does not
 * ship one, so the fuzz integration tests announce themselves as skipped rather
 * than failing on a machine that cannot build the fixture at all. The build
 * runs while the file is collected rather than in a hook, because collection is
 * when runIf reads the result.
 */
function buildFixture(): string | undefined {
  for (const mode of ["vulnerable", "fixed"]) {
    try {
      execFileSync("./build.sh", [mode], { cwd: FIXTURE, stdio: "pipe", timeout: BUILD_TIMEOUT_MS });
    } catch (error) {
      const reason = `${(error as Error).message}`.split("\n")[0];
      console.warn(`fuzz integration tests skipped, the fixture harness did not build: ${reason}`);
      return reason;
    }
  }
  return undefined;
}

const buildError = buildFixture();

afterAll(() => {
  rmSync(join(FIXTURE, ".crossfire"), { recursive: true, force: true });
});

function harnessBuilt(): boolean {
  return buildError === undefined;
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

const HEAP_OVERFLOW_REPORT = `==35547==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x604000036ff8 at pc 0x00010482d120
WRITE of size 34 at 0x604000036ff8 thread T0
    #0 0x00010482d11c in strcpy+0x534 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x4d11c)
    #1 0x0001041ac9bc in parse_request parse_request.c:32
    #2 0x0001041acaf0 in LLVMFuzzerTestOneInput parse_request_harness.c:19
    #3 0x0001041c86c4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) FuzzerLoop.cpp:619
    #4 0x0001041e4d10 in main FuzzerMain.cpp:20

0x604000036ff8 is located 0 bytes to the right of 40-byte region
allocated by thread T0 here:
    #0 0x000104834e24 in malloc+0x70 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x54e24)
    #1 0x0001041acacc in LLVMFuzzerTestOneInput parse_request_harness.c:17

SUMMARY: AddressSanitizer: heap-buffer-overflow parse_request.c:32 in parse_request
`;

describe("crash report parsing", () => {
  test("reads the kind and the application stack out of a sanitizer report", () => {
    const report = parseCrashReport(HEAP_OVERFLOW_REPORT);

    expect(report?.kind).toBe("heap-buffer-overflow");
    expect(report?.frames.map((frame) => frame.functionName)).toEqual([
      "parse_request",
      "LLVMFuzzerTestOneInput",
    ]);
    expect(report?.frames[0]).toMatchObject({ file: "parse_request.c", line: 32 });
  });

  test("ignores the allocation stack that follows the crash stack", () => {
    // The second stack also names LLVMFuzzerTestOneInput, at line 17. Picking it
    // up would put the malloc site in the signature.
    const report = parseCrashReport(HEAP_OVERFLOW_REPORT);

    expect(report?.frames).toHaveLength(2);
    expect(report?.frames.some((frame) => frame.line === 17)).toBe(false);
  });

  test("the signature ignores addresses and line numbers so one bug stays one finding", () => {
    const shifted = HEAP_OVERFLOW_REPORT.replaceAll("parse_request.c:32", "parse_request.c:44")
      .replaceAll("0x604000036ff8", "0x604000099aa0")
      .replaceAll("==35547==", "==41002==");

    expect(parseCrashReport(shifted)?.signature).toBe(parseCrashReport(HEAP_OVERFLOW_REPORT)?.signature);
  });

  test("a different crash kind in the same function is a different signature", () => {
    const useAfterFree = HEAP_OVERFLOW_REPORT.replaceAll(
      "heap-buffer-overflow",
      "heap-use-after-free",
    );

    expect(parseCrashReport(useAfterFree)?.signature).not.toBe(
      parseCrashReport(HEAP_OVERFLOW_REPORT)?.signature,
    );
  });

  test("reads libFuzzer's own failures", () => {
    expect(parseCrashReport("==1==ERROR: libFuzzer: deadly signal\n    #0 0x1 in boom src/a.c:3")?.kind).toBe(
      "deadly-signal",
    );
    expect(parseCrashReport("==1==ERROR: libFuzzer: timeout after 25 seconds\n")?.kind).toBe(
      "timeout",
    );
    expect(parseCrashReport("==1==ERROR: libFuzzer: out-of-memory (malloc(4096))\n")?.kind).toBe(
      "out-of-memory",
    );
  });

  test("a frame the symbolizer could not name still carries a name", () => {
    // Found by the crash-report fuzz harness: a frame in a stripped module is
    // nothing but an offset, and an empty name would collapse two stacks into
    // one signature.
    const stripped = parseCrashReport(
      "==1==ERROR: libFuzzer: deadly signal\n    #0 0x1041ac9bc +0x40\n    #1 0x1041acaf0 in boom src/a.c:3",
    );

    expect(stripped?.frames[0]?.functionName).toBe("<unknown>");
  });

  test("a frame with no usable line number is reported without one", () => {
    // Also from the harness: Finding.line is a positive integer, so line 0 has
    // to be absent rather than present and out of contract.
    const report = parseCrashReport(
      "==1==ERROR: libFuzzer: deadly signal\n    #0 0x1041ac9bc in boom src/a.c:0",
    );

    expect(report?.frames[0]).toEqual({ functionName: "boom", file: "src/a.c" });
  });

  test("a frame with a column keeps the file and the line apart", () => {
    // The symbolizer on Linux prints file:line:column and the one on macOS prints file:line,
    // so a greedy path read `src/a.c:3` as the file and 7 as the line. Every run was on
    // macOS, so this only surfaced when the gates first ran in CI.
    const withColumn = parseCrashReport(
      "==1==ERROR: libFuzzer: deadly signal\n    #0 0x1041ac9bc in boom src/a.c:3:7",
    );
    const withoutColumn = parseCrashReport(
      "==1==ERROR: libFuzzer: deadly signal\n    #0 0x1041ac9bc in boom src/a.c:3",
    );

    expect(withColumn?.frames[0]).toEqual({ functionName: "boom", file: "src/a.c", line: 3 });
    expect(withoutColumn?.frames[0]).toEqual(withColumn?.frames[0]);
  });

  test("output with no crash in it is not a crash report", () => {
    expect(parseCrashReport("Done 4096 runs in 2 second(s)\n")).toBeUndefined();
  });
});

describe("mapping a crash frame back into the repo", () => {
  test("relativizes an absolute path inside the repo", () => {
    expect(resolveRepoFile(join(FIXTURE, "src/parse_request.c"), FIXTURE, ["src"])).toBe(
      "src/parse_request.c",
    );
  });

  test("resolves the bare basename macOS symbolizers print", () => {
    expect(resolveRepoFile("parse_request.c", FIXTURE, ["src"])).toBe("src/parse_request.c");
  });

  test("refuses a path outside the repo", () => {
    expect(resolveRepoFile("/usr/include/string.h", FIXTURE, ["src"])).toBeUndefined();
  });

  test("refuses a basename that matches nothing in scope", () => {
    expect(resolveRepoFile("not_in_this_repo.c", FIXTURE, ["src"])).toBeUndefined();
  });
});

describe("libFuzzer engine against the fixture", () => {
  test.runIf(harnessBuilt())(
    "discovers, deduplicates, minimizes and emits the seeded crash",
    async () => {
      const result = await runFuzzers(fuzzConfig("build/parse-request-fuzzer", CRASH_BUDGET_MS));

      expect(result.runs).toHaveLength(1);
      expect(result.runs[0]).toMatchObject({
        detector: "fuzz",
        harness_id: "parse-request",
        status: "ok",
        findings_emitted: 1,
      });

      // One finding despite the engine re-finding the crash on later restarts:
      // the crash signature collapses them.
      expect(result.findings).toHaveLength(1);
      const finding = result.findings[0]!;
      expect(finding.source).toBe("fuzzer");
      expect(finding.confirmation_state).toBe("confirmed");
      expect(finding.class).toBe("heap-buffer-overflow");
      expect(finding.severity).toBe("high");
      expect(finding.file).toBe("src/parse_request.c");
      expect(finding.id).toMatch(/^fuzz-[0-9a-f]{12}$/);

      const artifact = finding.crash_artifact!;
      expect(artifact).toBe(`.crossfire/crashes/parse-request/${finding.id}.min`);
      const minimized = join(FIXTURE, artifact);
      const raw = join(FIXTURE, `.crossfire/crashes/parse-request/${finding.id}.raw`);
      expect(existsSync(minimized)).toBe(true);
      // The raw input is kept alongside the minimized one so an over-eager
      // signature is recoverable.
      expect(existsSync(raw)).toBe(true);

      // The true minimum is 33 bytes: a space plus the 32 path bytes it takes to
      // run off the end of request.path. The bound leaves room for the
      // minimizer stopping a little short without letting a raw input pass.
      const minimizedSize = statSync(minimized).size;
      expect(minimizedSize).toBeLessThanOrEqual(statSync(raw).size);
      expect(minimizedSize).toBeGreaterThanOrEqual(33);
      expect(minimizedSize).toBeLessThanOrEqual(128);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test.runIf(harnessBuilt())(
    "the emitted artifact replays through the repro command",
    async () => {
      const result = await runFuzzers(fuzzConfig("build/parse-request-fuzzer", CRASH_BUDGET_MS));
      const finding = result.findings[0]!;

      const survived = await runTool("sh", ["-c", finding.repro_command], {
        cwd: FIXTURE,
        timeoutMs: 60_000,
      });
      // Exit 0 means reproduced, per the repro convention.
      expect(survived.exitCode).toBe(0);

      const fixedHarness = finding.repro_command.replace(
        "parse-request-fuzzer",
        "parse-request-fuzzer-fixed",
      );
      const closed = await runTool("sh", ["-c", fixedHarness], { cwd: FIXTURE, timeoutMs: 60_000 });
      expect(closed.exitCode).not.toBe(0);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test.runIf(harnessBuilt())(
    "the fixed harness yields nothing within budget",
    async () => {
      const result = await runFuzzers(
        fuzzConfig("build/parse-request-fuzzer-fixed", CLEAN_BUDGET_MS),
      );

      expect(result.runs[0]).toMatchObject({ status: "ok", findings_emitted: 0 });
      expect(result.findings).toEqual([]);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test.runIf(harnessBuilt())(
    "an unbuilt harness is an error, not an empty pass",
    async () => {
      const result = await runFuzzers(fuzzConfig("build/not-built-yet", CLEAN_BUDGET_MS));

      expect(result.runs[0]?.status).toBe("error");
      expect(result.runs[0]?.note).toContain("not built");
      expect(result.findings).toEqual([]);
    },
    FUZZ_TEST_TIMEOUT_MS,
  );

  test("an unimplemented engine is an error rather than a silent skip", async () => {
    const base = loadRunConfig(SAMPLE_CONFIG);
    const harness = base.detectors.fuzz.harnesses[0]!;
    const config: RunConfig = {
      ...base,
      detectors: {
        ...base.detectors,
        fuzz: {
          ...base.detectors.fuzz,
          harnesses: [{ ...harness, language: "python", engine: "atheris" }],
        },
      },
    };

    const result = await runFuzzers(config);

    expect(result.runs[0]?.status).toBe("error");
    expect(result.runs[0]?.note).toContain("atheris");
  });

  test("a disabled fuzz block produces a skipped run", async () => {
    const base = loadRunConfig(SAMPLE_CONFIG);
    const result = await runFuzzers({
      ...base,
      detectors: { ...base.detectors, fuzz: { ...base.detectors.fuzz, enabled: false } },
    });

    expect(result.runs[0]?.status).toBe("skipped");
    expect(result.findings).toEqual([]);
  });
});
