import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";

import type { RunConfig } from "../src/config/index.js";
import { loadRunConfig } from "../src/config/index.js";
import type { Finding } from "../src/contracts/index.js";
import {
  dedupeFindings,
  normalizeOsvOutput,
  normalizeSemgrepOutput,
  runScanners,
  runTool,
} from "../src/detection/index.js";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const FIXTURE = resolve(REPO_ROOT, "fixtures/vulnerable-repo");
const SAMPLE_CONFIG = resolve(REPO_ROOT, "crossfire.sample.json");
const SCAN_TIMEOUT_MS = 120_000;

function hasBinary(name: string): boolean {
  try {
    execFileSync("sh", ["-c", `command -v ${name}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function fixtureConfig(overrides: (config: RunConfig) => RunConfig): RunConfig {
  return overrides(loadRunConfig(SAMPLE_CONFIG));
}

function onlySemgrep(config: RunConfig): RunConfig {
  return {
    ...config,
    detectors: {
      ...config.detectors,
      osvScanner: { ...config.detectors.osvScanner, enabled: false },
      fuzz: { ...config.detectors.fuzz, enabled: false },
    },
  };
}

function onlyOsv(config: RunConfig): RunConfig {
  return {
    ...config,
    detectors: {
      ...config.detectors,
      semgrep: { ...config.detectors.semgrep, enabled: false },
      fuzz: { ...config.detectors.fuzz, enabled: false },
    },
  };
}

/** The 1-based line of the seeded strcpy, so the test survives an edit above it. */
function seededStrcpyLine(): number {
  const source = readFileSync(join(FIXTURE, "src/parse_request.c"), "utf8").split("\n");
  const index = source.findIndex((line) => line.includes("strcpy(out->path"));
  expect(index).toBeGreaterThanOrEqual(0);
  return index + 1;
}

describe("semgrep scanner", () => {
  test.runIf(hasBinary("semgrep"))(
    "surfaces the seeded finding as a candidate with the right file and class",
    async () => {
      const result = await runScanners(fixtureConfig(onlySemgrep));

      expect(result.runs.map((run) => [run.detector, run.status])).toEqual([
        ["semgrep", "ok"],
        ["osv-scanner", "skipped"],
      ]);
      expect(result.findings).toHaveLength(1);

      const finding = result.findings[0]!;
      expect(finding.source).toBe("sast");
      expect(finding.confirmation_state).toBe("candidate");
      expect(finding.file).toBe("src/parse_request.c");
      expect(finding.class).toBe("out-of-bounds-write");
      expect(finding.line).toBe(seededStrcpyLine());
      expect(finding.severity).toBe("high");
      expect(finding.id).toMatch(/^sast-[0-9a-f]{12}$/);
      expect(finding.repro_command).toContain("crossfire-insecure-strcpy");
    },
    SCAN_TIMEOUT_MS,
  );

  test.runIf(hasBinary("semgrep"))(
    "a clean directory yields no findings",
    async () => {
      const clean = mkdtempSync(join(tmpdir(), "crossfire-clean-"));
      mkdirSync(join(clean, "src"));
      writeFileSync(
        join(clean, "src/safe.c"),
        [
          "#include <string.h>",
          "void copy_path(char *dst, size_t cap, const char *src) {",
          "  size_t len = strlen(src);",
          "  if (len < cap) { memcpy(dst, src, len + 1); }",
          "}",
          "",
        ].join("\n"),
      );

      const config = fixtureConfig((base) => ({
        ...onlySemgrep(base),
        target: { ...base.target, repoPath: clean },
        detectors: {
          ...onlySemgrep(base).detectors,
          semgrep: {
            ...base.detectors.semgrep,
            ruleset: join(FIXTURE, ".semgrep/crossfire-c.yml"),
          },
        },
      }));

      const result = await runScanners(config);

      expect(result.runs[0]?.status).toBe("ok");
      expect(result.findings).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );

  test("normalizes a rule without CWE metadata using the check id", () => {
    const findings = normalizeSemgrepOutput(
      {
        results: [
          {
            check_id: "c.lang.security.insecure-use-gets-fn.insecure-use-gets-fn",
            path: "src/input.c",
            start: { line: 12 },
            extra: { message: "gets is unbounded", severity: "WARNING" },
          },
        ],
      },
      { enabled: true, ruleset: "p/security-audit", timeBudgetMs: 1000 },
      FIXTURE,
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.class).toBe("insecure-use-gets-fn");
    expect(findings[0]?.severity).toBe("medium");
    expect(findings[0]?.line).toBe(12);
  });

  test("a finding keeps its id when a fix above it shifts the line", () => {
    // The defect this pins: a fix shifts every line below it, and a line keyed
    // id turned the finding it had just closed into a brand new one.
    const source = readFileSync(resolve(FIXTURE, "src/parse_request.c"), "utf8");
    const flagged = "strcpy(out->path, path)";
    const at = source.indexOf(flagged);
    expect(at).toBeGreaterThan(-1);

    const matchAt = (offset: number, line: number) =>
      normalizeSemgrepOutput(
        {
          results: [
            {
              check_id: "c.lang.security.insecure-use-string-copy-fn",
              path: "src/parse_request.c",
              start: { line, offset },
              end: { offset: offset + flagged.length },
              extra: { severity: "WARNING" },
            },
          ],
        },
        { enabled: true, ruleset: "p/security-audit", timeBudgetMs: 1000 },
        FIXTURE,
      )[0];

    const before = matchAt(at, 30);
    // The same construct, reported four lines lower after an edit above it.
    const after = matchAt(at, 34);

    expect(before?.id).toBe(after?.id);
    expect(before?.line).toBe(30);
    expect(after?.line).toBe(34);
  });

  test("a different construct in the same file is a different finding", () => {
    const source = readFileSync(resolve(FIXTURE, "src/parse_request.c"), "utf8");
    const idFor = (flagged: string) => {
      const at = source.indexOf(flagged);
      expect(at).toBeGreaterThan(-1);
      return normalizeSemgrepOutput(
        {
          results: [
            {
              check_id: "c.lang.security.insecure-use-string-copy-fn",
              path: "src/parse_request.c",
              start: { line: 1, offset: at },
              end: { offset: at + flagged.length },
              extra: { severity: "WARNING" },
            },
          ],
        },
        { enabled: true, ruleset: "p/security-audit", timeBudgetMs: 1000 },
        FIXTURE,
      )[0]?.id;
    };

    expect(idFor("strcpy(out->path, path)")).not.toBe(idFor("memcpy(out->method, line, method_len)"));
  });

  test("drops the line when semgrep reports no location", () => {
    const findings = normalizeSemgrepOutput(
      {
        results: [
          {
            check_id: "rules.whole-file",
            path: "src/input.c",
            start: { line: 0 },
            extra: { severity: "INFO" },
          },
        ],
      },
      { enabled: true, ruleset: "p/security-audit", timeBudgetMs: 1000 },
      FIXTURE,
    );

    expect(findings[0]?.line).toBeUndefined();
    expect(findings[0]?.severity).toBe("low");
  });
});

describe("osv-scanner", () => {
  test.runIf(hasBinary("osv-scanner"))(
    "surfaces the seeded vulnerable dependency as a candidate",
    async () => {
      const result = await runScanners(fixtureConfig(onlyOsv));

      expect(result.runs.map((run) => [run.detector, run.status])).toEqual([
        ["semgrep", "skipped"],
        ["osv-scanner", "ok"],
      ]);
      expect(result.findings.length).toBeGreaterThan(0);

      for (const finding of result.findings) {
        expect(finding.source).toBe("sca");
        expect(finding.confirmation_state).toBe("candidate");
        expect(finding.class).toBe("vulnerable-dependency");
        expect(finding.file).toBe("package-lock.json");
        expect(finding.description).toContain("minimist@1.2.0");
      }

      const advisories = result.findings.map((finding) => finding.repro_command).join(" ");
      expect(advisories).toContain("GHSA-");
    },
    SCAN_TIMEOUT_MS,
  );

  test("normalizes an advisory group into a candidate finding", () => {
    const findings = normalizeOsvOutput(
      {
        results: [
          {
            source: { path: "/repo/package-lock.json" },
            packages: [
              {
                package: { name: "minimist", version: "1.2.0", ecosystem: "npm" },
                vulnerabilities: [
                  { id: "GHSA-xvch-5gv4-984h", summary: "Prototype Pollution in minimist" },
                ],
                groups: [
                  {
                    ids: ["GHSA-xvch-5gv4-984h"],
                    aliases: ["CVE-2021-44906", "GHSA-xvch-5gv4-984h"],
                    max_severity: "9.8",
                  },
                ],
              },
            ],
          },
        ],
      },
      "/repo",
    );

    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toMatch(/^sca-[0-9a-f]{12}$/);
    expect(finding.file).toBe("package-lock.json");
    expect(finding.severity).toBe("critical");
    expect(finding.description).toContain("CVE-2021-44906");
    expect(finding.description).not.toContain("GHSA-xvch-5gv4-984h (GHSA-xvch-5gv4-984h");
    expect(finding.repro_command).toBe(
      "osv-scanner scan source --lockfile='package-lock.json' --format=json | grep -q 'GHSA-xvch-5gv4-984h'",
    );
  });

  test("maps CVSS bands onto the severity scale and floors unscored advisories", () => {
    const severityFor = (maxSeverity?: string): string =>
      normalizeOsvOutput(
        {
          results: [
            {
              source: { path: "lock.json" },
              packages: [
                {
                  package: { name: "pkg", version: "1.0.0", ecosystem: "npm" },
                  groups: [
                    {
                      ids: ["OSV-1"],
                      ...(maxSeverity === undefined ? {} : { max_severity: maxSeverity }),
                    },
                  ],
                },
              ],
            },
          ],
        },
        "/repo",
      )[0]!.severity;

    expect(severityFor("9.8")).toBe("critical");
    expect(severityFor("7.5")).toBe("high");
    expect(severityFor("5.6")).toBe("medium");
    expect(severityFor("2.1")).toBe("low");
    expect(severityFor(undefined)).toBe("medium");
  });
});

describe("cross scanner deduplication", () => {
  function candidate(overrides: Partial<Finding>): Finding {
    return {
      id: "sast-000000000000",
      source: "sast",
      confirmation_state: "candidate",
      severity: "medium",
      class: "out-of-bounds-write",
      file: "src/parse_request.c",
      line: 32,
      description: "unbounded copy",
      repro_command: "true",
      expected_secure_behavior: "bounded copy",
      ...overrides,
    };
  }

  test("collapses findings that share an id, keeping the more severe report", () => {
    const result = dedupeFindings([
      candidate({ description: "reported by scanner a" }),
      candidate({ severity: "high", description: "reported by scanner b" }),
    ]);

    expect(result.duplicatesDropped).toBe(1);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe("high");
    expect(result.findings[0]?.description).toBe("reported by scanner b");
  });

  test("keeps distinct findings and orders them deterministically", () => {
    const forward = dedupeFindings([
      candidate({ id: "sca-b", file: "package-lock.json", line: undefined }),
      candidate({ id: "sast-a", file: "src/parse_request.c", line: 32 }),
    ]);
    const reversed = dedupeFindings([
      candidate({ id: "sast-a", file: "src/parse_request.c", line: 32 }),
      candidate({ id: "sca-b", file: "package-lock.json", line: undefined }),
    ]);

    expect(forward.duplicatesDropped).toBe(0);
    expect(forward.findings.map((finding) => finding.id)).toEqual(["sca-b", "sast-a"]);
    expect(reversed.findings.map((finding) => finding.id)).toEqual(
      forward.findings.map((finding) => finding.id),
    );
  });
});

describe("detector subprocess handling", () => {
  test("a missing binary is reported, not swallowed", async () => {
    const result = await runTool("crossfire-no-such-detector", [], {
      cwd: REPO_ROOT,
      timeoutMs: 5_000,
    });

    expect(result.spawnError).toMatch(/ENOENT/);
    expect(result.exitCode).toBeNull();
  });

  test("a blown time budget is reported as a timeout", async () => {
    const result = await runTool("sh", ["-c", "sleep 5"], { cwd: REPO_ROOT, timeoutMs: 300 });

    expect(result.timedOut).toBe(true);
  });

  test("disabled scanners produce skipped runs rather than silence", async () => {
    const config = fixtureConfig((base) => ({
      ...base,
      detectors: {
        ...base.detectors,
        semgrep: { ...base.detectors.semgrep, enabled: false },
        osvScanner: { ...base.detectors.osvScanner, enabled: false },
      },
    }));

    const result = await runScanners(config);

    expect(result.runs.map((run) => run.status)).toEqual(["skipped", "skipped"]);
    expect(result.findings).toEqual([]);
  });
});
