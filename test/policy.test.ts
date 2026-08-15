import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";

import { DEFAULT_EXCLUDED_PATHS, loadRunConfig } from "../src/config/index.js";
import type { RunConfig } from "../src/config/index.js";
import { runFuzzers, runScanners } from "../src/detection/index.js";
import { PolicyError, createPathScope, createPermissionPolicy } from "../src/policy/index.js";

const SAMPLE_CONFIG = resolve(import.meta.dirname, "..", "crossfire.sample.json");

function makeRepo(): string {
  const repo = mkdtempSync(join(tmpdir(), "crossfire-policy-"));
  mkdirSync(join(repo, "src/nested"), { recursive: true });
  mkdirSync(join(repo, "secrets"), { recursive: true });
  mkdirSync(join(repo, "config"), { recursive: true });
  writeFileSync(join(repo, "src/app.c"), "int main(void) { return 0; }\n");
  writeFileSync(join(repo, "src/nested/.env"), "NESTED=1\n");
  writeFileSync(join(repo, ".env"), "API_KEY=secret\n");
  writeFileSync(join(repo, ".env.local"), "API_KEY=secret\n");
  writeFileSync(join(repo, "secrets/token.txt"), "token\n");
  writeFileSync(join(repo, "config/server.pem"), "key material\n");
  return repo;
}

function scopeFor(repo: string, extra: readonly string[] = []) {
  return createPathScope(repo, [...DEFAULT_EXCLUDED_PATHS, ...extra]);
}

describe("exclusion path matcher", () => {
  test("allows an ordinary in-scope source file", () => {
    const repo = makeRepo();
    const decision = scopeFor(repo).check(join(repo, "src/app.c"));

    expect(decision.allowed).toBe(true);
    expect(decision.relativePath).toBe("src/app.c");
  });

  test("accepts a repo relative path as readily as an absolute one", () => {
    const repo = makeRepo();
    const scope = scopeFor(repo);

    expect(scope.check("src/app.c").relativePath).toBe("src/app.c");
    expect(scope.check(join(repo, "src/app.c")).relativePath).toBe("src/app.c");
  });

  test.each([
    [".env", ".env"],
    ["a suffixed env file", ".env.local"],
    ["a nested env file", "src/nested/.env"],
    ["anything under secrets", "secrets/token.txt"],
    ["the secrets directory itself", "secrets"],
    ["private key material", "config/server.pem"],
  ])("denies %s", (_label, path) => {
    const repo = makeRepo();
    const decision = scopeFor(repo).check(join(repo, path));

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("excluded path");
  });

  test("denies a path that climbs out of the repo", () => {
    const repo = makeRepo();
    const decision = scopeFor(repo).check(join(repo, "../../etc/passwd"));

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("outside the target repo");
  });

  test("denies an absolute path that was never in the repo", () => {
    const repo = makeRepo();

    expect(scopeFor(repo).check("/etc/passwd").allowed).toBe(false);
  });

  test("denies a symlink that points out of the repo", () => {
    const repo = makeRepo();
    symlinkSync("/etc/passwd", join(repo, "src/escape.txt"));

    const decision = scopeFor(repo).check(join(repo, "src/escape.txt"));

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("outside the target repo");
  });

  test("denies a symlink that points at an excluded file inside the repo", () => {
    const repo = makeRepo();
    symlinkSync(join(repo, ".env"), join(repo, "src/looks-innocent.txt"));

    const decision = scopeFor(repo).check(join(repo, "src/looks-innocent.txt"));

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("excluded path");
  });

  test("judges a file that does not exist yet by where it would land", () => {
    const repo = makeRepo();
    const scope = scopeFor(repo);

    expect(scope.check(join(repo, "src/brand-new.c")).allowed).toBe(true);
    expect(scope.check(join(repo, "secrets/brand-new.txt")).allowed).toBe(false);
  });

  test("honours user supplied exclusions alongside the secret defaults", () => {
    const repo = makeRepo();
    mkdirSync(join(repo, "build"), { recursive: true });
    writeFileSync(join(repo, "build/out.o"), "");

    expect(scopeFor(repo, ["build/**"]).check(join(repo, "build/out.o")).allowed).toBe(false);
    expect(scopeFor(repo).check(join(repo, "build/out.o")).allowed).toBe(true);
  });

  test("denies an empty path", () => {
    const repo = makeRepo();

    expect(scopeFor(repo).check("   ").allowed).toBe(false);
  });

  test("refuses to scope a repo that does not exist", () => {
    expect(() => createPathScope(resolve("/nope/crossfire-missing"), [])).toThrow(PolicyError);
  });
});

describe("per agent permission policy", () => {
  test("Grok may read but never write", () => {
    const repo = makeRepo();
    const grok = createPermissionPolicy("grok", scopeFor(repo));

    expect(grok.readFile(join(repo, "src/app.c")).allowed).toBe(true);
    const write = grok.writeFile(join(repo, "src/app.c"));
    expect(write.allowed).toBe(false);
    expect(write.reason).toContain("grok has no write access");
  });

  test("Claude may write in-scope source", () => {
    const repo = makeRepo();
    const claude = createPermissionPolicy("claude", scopeFor(repo));

    expect(claude.writeFile(join(repo, "src/app.c")).allowed).toBe(true);
  });

  test.each(["claude", "grok"] as const)("%s is denied excluded paths either way", (agent) => {
    const repo = makeRepo();
    const policy = createPermissionPolicy(agent, scopeFor(repo));

    expect(policy.readFile(join(repo, ".env")).allowed).toBe(false);
    expect(policy.writeFile(join(repo, ".env")).allowed).toBe(false);
  });

  test("Grok keeps execute and read tool calls, loses write ones", () => {
    const repo = makeRepo();
    const grok = createPermissionPolicy("grok", scopeFor(repo));
    const paths = [join(repo, "src/app.c")];

    expect(grok.toolCall({ title: "run tests", access: "execute", paths }).allowed).toBe(true);
    expect(grok.toolCall({ title: "read source", access: "read", paths }).allowed).toBe(true);
    expect(grok.toolCall({ title: "patch source", access: "write", paths }).allowed).toBe(false);
  });

  test("Claude keeps write tool calls", () => {
    const repo = makeRepo();
    const claude = createPermissionPolicy("claude", scopeFor(repo));

    expect(
      claude.toolCall({ title: "patch", access: "write", paths: [join(repo, "src/app.c")] }).allowed,
    ).toBe(true);
  });

  test("a tool call naming an excluded path is denied whatever it claims to do", () => {
    const repo = makeRepo();
    const claude = createPermissionPolicy("claude", scopeFor(repo));

    const decision = claude.toolCall({
      title: "read config",
      access: "read",
      paths: [join(repo, "src/app.c"), join(repo, ".env")],
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("excluded path");
  });

  test("a tool call naming no paths is judged on what it does", () => {
    const repo = makeRepo();
    const grok = createPermissionPolicy("grok", scopeFor(repo));

    expect(grok.toolCall({ title: "think", access: "other", paths: [] }).allowed).toBe(true);
    expect(grok.toolCall({ title: "edit", access: "write", paths: [] }).allowed).toBe(false);
  });
});

describe("detectors run under the same exclusion set", () => {
  function excluding(patterns: readonly string[]): RunConfig {
    const config = loadRunConfig(SAMPLE_CONFIG);
    return {
      ...config,
      target: { ...config.target, excludedPaths: [...config.target.excludedPaths, ...patterns] },
    };
  }

  test("a scanner will not open an excluded lockfile", async () => {
    const config = excluding(["package-lock.json"]);
    const result = await runScanners({
      ...config,
      detectors: {
        ...config.detectors,
        semgrep: { ...config.detectors.semgrep, enabled: false },
      },
    });

    const osv = result.runs.find((run) => run.detector === "osv-scanner");
    expect(osv?.status).toBe("skipped");
    expect(osv?.note).toContain("outside the scope or excluded");
    expect(result.findings).toEqual([]);
  });

  test("a scanner will not walk an excluded source directory", async () => {
    const config = excluding(["src/**", "src"]);
    const result = await runScanners({
      ...config,
      detectors: {
        ...config.detectors,
        osvScanner: { ...config.detectors.osvScanner, enabled: false },
      },
    });

    const semgrep = result.runs.find((run) => run.detector === "semgrep");
    expect(semgrep?.status).toBe("skipped");
    expect(semgrep?.note).toContain("every in-scope directory is excluded");
  });

  test("the fuzzer will not run a harness the exclusion set covers", async () => {
    const result = await runFuzzers(excluding(["build/**"]));

    expect(result.runs[0]?.status).toBe("error");
    expect(result.runs[0]?.note).toContain("out of scope");
    expect(result.findings).toEqual([]);
  });

  test("the fuzzer will not read an excluded corpus", async () => {
    const result = await runFuzzers(excluding(["fuzz/corpus/**"]));

    expect(result.runs[0]?.status).toBe("error");
    expect(result.runs[0]?.note).toContain("out of scope");
  });
});
