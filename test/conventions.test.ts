import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, test } from "vitest";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const EM_DASH = String.fromCodePoint(0x2014);

function emDashLines(text: string): number[] {
  return text
    .split("\n")
    .map((line, index) => (line.includes(EM_DASH) ? index + 1 : 0))
    .filter((lineNumber) => lineNumber > 0);
}

function trackedFiles(): string[] {
  const output = execFileSync("git", ["ls-files", "-z"], { cwd: REPO_ROOT, encoding: "utf8" });
  return output
    .split("\0")
    .filter((file) => file.length > 0)
    .filter((file) => existsSync(resolve(REPO_ROOT, file)));
}

describe("CLAUDE.md conventions", () => {
  test("the constitution sits at the repo root", () => {
    expect(readFileSync(resolve(REPO_ROOT, "CLAUDE.md"), "utf8")).toContain("Golden rules");
  });

  test("the em dash detector finds an em dash", () => {
    expect(emDashLines(`ok\nnot ok ${EM_DASH} here\n`)).toEqual([2]);
    expect(emDashLines("plain, honest punctuation")).toEqual([]);
  });

  test("no tracked file contains an em dash", () => {
    const offenders: string[] = [];
    for (const file of trackedFiles()) {
      if (file === "package-lock.json") {
        continue;
      }
      for (const line of emDashLines(readFileSync(resolve(REPO_ROOT, file), "utf8"))) {
        offenders.push(`${file}:${line}`);
      }
    }

    expect(offenders).toEqual([]);
  });
});
