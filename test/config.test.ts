import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";

import { ConfigError, DEFAULT_EXCLUDED_PATHS, loadRunConfig } from "../src/config/index.js";

const SAMPLE_CONFIG_PATH = resolve(import.meta.dirname, "..", "crossfire.sample.json");

function writeConfig(contents: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "crossfire-config-"));
  const path = join(dir, "crossfire.json");
  writeFileSync(path, typeof contents === "string" ? contents : JSON.stringify(contents, null, 2));
  return path;
}

function minimalConfig(): Record<string, unknown> {
  return {
    task: "Close memory safety bugs in the parser",
    target: {
      repoPath: "./target",
      inScopeDirs: ["src"],
      testCommand: "npm test",
    },
    detectors: {
      semgrep: { ruleset: "p/security-audit", timeBudgetMs: 120_000 },
      osvScanner: { lockfiles: ["package-lock.json"], timeBudgetMs: 60_000 },
      fuzz: {
        timeBudgetMs: 300_000,
        harnesses: [
          {
            id: "parse-json",
            language: "python",
            engine: "atheris",
            entryPoint: "fuzz/parse_json_harness.py",
            corpusDir: "fuzz/corpus/parse-json",
          },
        ],
      },
    },
  };
}

describe("loadRunConfig", () => {
  test("loads and validates the sample config", () => {
    const config = loadRunConfig(SAMPLE_CONFIG_PATH);

    expect(config.task.length).toBeGreaterThan(0);
    expect(config.target.inScopeDirs.length).toBeGreaterThan(0);
    expect(config.detectors.fuzz.harnesses.length).toBeGreaterThan(0);
    expect(config.detectors.fuzz.harnesses[0]?.engine).toBe("libfuzzer");
  });

  test("resolves the target repo path against the config file directory", () => {
    const path = writeConfig(minimalConfig());

    const config = loadRunConfig(path);

    expect(config.target.repoPath).toBe(resolve(path, "..", "target"));
  });

  test("applies loop defaults when the loop block is omitted", () => {
    const config = loadRunConfig(writeConfig(minimalConfig()));

    expect(config.loop.iterationCap).toBe(5);
    expect(config.loop.severityBar).toBe("medium");
    expect(config.loop.turnTimeoutMs).toBeGreaterThan(0);
  });

  test("keeps explicit loop settings", () => {
    const raw = minimalConfig();
    raw.loop = { iterationCap: 12, severityBar: "high", turnTimeoutMs: 90_000 };

    const config = loadRunConfig(writeConfig(raw));

    expect(config.loop).toEqual({ iterationCap: 12, severityBar: "high", turnTimeoutMs: 90_000 });
  });

  test("merges user exclusions on top of the secret defaults", () => {
    const raw = minimalConfig();
    (raw.target as Record<string, unknown>).excludedPaths = ["build/**", ".env*"];

    const config = loadRunConfig(writeConfig(raw));

    for (const pattern of DEFAULT_EXCLUDED_PATHS) {
      expect(config.target.excludedPaths).toContain(pattern);
    }
    expect(config.target.excludedPaths).toContain("build/**");
    expect(config.target.excludedPaths.filter((p) => p === ".env*")).toHaveLength(1);
  });

  test("defaults excluded paths to the secret set when omitted", () => {
    const config = loadRunConfig(writeConfig(minimalConfig()));

    expect(config.target.excludedPaths).toEqual([...DEFAULT_EXCLUDED_PATHS]);
    expect(config.target.excludedPaths).toContain(".env*");
  });

  test("rejects an unknown top level key", () => {
    const raw = minimalConfig();
    raw.mode = "yolo";

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/mode/);
  });

  test("rejects an unknown key inside the target block", () => {
    const raw = minimalConfig();
    (raw.target as Record<string, unknown>).writeEverywhere = true;

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/target.writeEverywhere/);
  });

  test("rejects a missing required field naming the field path", () => {
    const raw = minimalConfig();
    delete (raw.target as Record<string, unknown>).testCommand;

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/target\.testCommand/);
  });

  test("rejects an empty in-scope directory list", () => {
    const raw = minimalConfig();
    (raw.target as Record<string, unknown>).inScopeDirs = [];

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/target\.inScopeDirs/);
  });

  test("rejects a non-positive iteration cap", () => {
    const raw = minimalConfig();
    raw.loop = { iterationCap: 0 };

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/loop\.iterationCap/);
  });

  test("rejects a non-positive detector time budget", () => {
    const raw = minimalConfig();
    (raw.detectors as Record<string, Record<string, unknown>>).semgrep!.timeBudgetMs = 0;

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/detectors\.semgrep\.timeBudgetMs/);
  });

  test("rejects an unknown fuzz engine", () => {
    const raw = minimalConfig();
    const fuzz = (raw.detectors as Record<string, Record<string, unknown>>).fuzz!;
    (fuzz.harnesses as Record<string, unknown>[])[0]!.engine = "hyperfuzz";

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/engine/);
  });

  test("rejects a fuzz engine that does not support the harness language", () => {
    const raw = minimalConfig();
    const fuzz = (raw.detectors as Record<string, Record<string, unknown>>).fuzz!;
    (fuzz.harnesses as Record<string, unknown>[])[0]!.engine = "jazzer";

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/jazzer/);
  });

  test("rejects duplicate harness ids", () => {
    const raw = minimalConfig();
    const fuzz = (raw.detectors as Record<string, Record<string, unknown>>).fuzz!;
    const harnesses = fuzz.harnesses as Record<string, unknown>[];
    harnesses.push({ ...harnesses[0] });

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(/parse-json/);
  });

  test("rejects malformed JSON with the file path in the message", () => {
    const path = writeConfig("{ not json ]");

    expect(() => loadRunConfig(path)).toThrow(new RegExp(path.replace(/[/\\]/g, "\\$&")));
  });

  test("rejects a missing config file with a clear error", () => {
    const path = join(mkdtempSync(join(tmpdir(), "crossfire-config-")), "absent.json");

    expect(() => loadRunConfig(path)).toThrow(ConfigError);
    expect(() => loadRunConfig(path)).toThrow(/not found/i);
  });

  test("throws ConfigError, not a raw zod error", () => {
    const raw = minimalConfig();
    raw.task = "";

    expect(() => loadRunConfig(writeConfig(raw))).toThrow(ConfigError);
  });
});
