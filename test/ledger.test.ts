import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import {
  GENESIS_HASH,
  LedgerWriter,
  computeEntryHash,
  hashPayload,
  readLedger,
  verifyLedger,
} from "../src/ledger/index.js";
import type { LedgerEntryBody } from "../src/contracts/index.js";

function ledgerPath(): string {
  return join(mkdtempSync(join(tmpdir(), "crossfire-ledger-")), "ledger.jsonl");
}

function body(round: number, overrides: Partial<LedgerEntryBody> = {}): LedgerEntryBody {
  return {
    round,
    started_at: "2026-08-15T10:00:00.000Z",
    ended_at: "2026-08-15T10:04:30.000Z",
    detector_runs: [
      {
        detector: "fuzz",
        harness_id: "parse-request",
        status: "ok",
        duration_ms: 120_000,
        findings_emitted: 1,
      },
      { detector: "semgrep", status: "ok", duration_ms: 8_000, findings_emitted: 2 },
    ],
    findings_hash: "a".repeat(64),
    fixes_hash: "b".repeat(64),
    verify_results: [
      { finding_id: "fuzz-parse-request-9f21", outcome: "closed", exit_code: 1, duration_ms: 900 },
    ],
    test_result: { status: "pass", command: "npm test", exit_code: 0, duration_ms: 4_200 },
    git_sha: "0123456789abcdef0123456789abcdef01234567",
    ...overrides,
  };
}

function lines(path: string): string[] {
  return readFileSync(path, "utf8").split("\n").filter((line) => line.length > 0);
}

describe("hashPayload", () => {
  test("hashes the findings and fixes a round is built from", () => {
    const batch = { round: 1, findings: [{ id: "fuzz-1", severity: "high" }] };

    expect(hashPayload(batch)).toMatch(/^[0-9a-f]{64}$/);
  });

  test("ignores key order so a reserialized payload hashes the same", () => {
    const one = { round: 1, findings: [{ id: "fuzz-1", severity: "high" }] };
    const other = { findings: [{ severity: "high", id: "fuzz-1" }], round: 1 };

    expect(hashPayload(one)).toBe(hashPayload(other));
  });

  test("changes when any value changes", () => {
    const batch = { round: 1, findings: [{ id: "fuzz-1", severity: "high" }] };
    const changed = { round: 1, findings: [{ id: "fuzz-1", severity: "low" }] };

    expect(hashPayload(batch)).not.toBe(hashPayload(changed));
  });

  test("distinguishes array order", () => {
    expect(hashPayload(["a", "b"])).not.toBe(hashPayload(["b", "a"]));
  });

  test("hashes an empty round of findings to a stable digest", () => {
    expect(hashPayload({ round: 1, findings: [] })).toBe(hashPayload({ findings: [], round: 1 }));
  });
});

describe("LedgerWriter", () => {
  test("writes one JSONL line per round", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);

    writer.append(body(1));
    writer.append(body(2));

    expect(lines(path)).toHaveLength(2);
  });

  test("chains the first entry to the genesis hash", () => {
    const path = ledgerPath();
    const first = new LedgerWriter(path).append(body(1));

    expect(first.prev_hash).toBe(GENESIS_HASH);
    expect(first.entry_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("links each entry to the hash of the one before it", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);

    const first = writer.append(body(1));
    const second = writer.append(body(2));
    const third = writer.append(body(3));

    expect(second.prev_hash).toBe(first.entry_hash);
    expect(third.prev_hash).toBe(second.entry_hash);
  });

  test("computes the entry hash over the entry content and its link", () => {
    const path = ledgerPath();
    const entry = new LedgerWriter(path).append(body(1));
    const { entry_hash, ...rest } = entry;

    expect(computeEntryHash(rest)).toBe(entry_hash);
  });

  test("refuses a round that does not follow the last entry", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));

    expect(() => writer.append(body(3))).toThrow(/round/i);
    expect(() => writer.append(body(1))).toThrow(/round/i);
  });

  test("refuses a malformed entry", () => {
    const writer = new LedgerWriter(ledgerPath());

    expect(() => writer.append(body(1, { git_sha: "not-a-sha" }))).toThrow(/git_sha/);
  });

  test("keeps prior entries byte for byte when appending", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    const afterFirst = readFileSync(path, "utf8");

    writer.append(body(2));

    expect(readFileSync(path, "utf8").startsWith(afterFirst)).toBe(true);
  });

  test("continues an existing chain across writer instances", () => {
    const path = ledgerPath();
    const first = new LedgerWriter(path).append(body(1));

    const second = new LedgerWriter(path).append(body(2));

    expect(second.prev_hash).toBe(first.entry_hash);
    expect(verifyLedger(path).ok).toBe(true);
  });
});

describe("readLedger", () => {
  test("returns entries in order", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));

    expect(readLedger(path).map((entry) => entry.round)).toEqual([1, 2]);
  });

  test("returns nothing for an empty ledger file", () => {
    const path = ledgerPath();
    writeFileSync(path, "");

    expect(readLedger(path)).toEqual([]);
  });
});

describe("verifyLedger", () => {
  test("verifies an untouched chain", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));
    writer.append(body(3));

    expect(verifyLedger(path)).toEqual({ ok: true, entries: 3 });
  });

  test("verifies an entry whose keys were reserialized in another order", () => {
    const path = ledgerPath();
    const entry = new LedgerWriter(path).append(body(1));
    const reordered = Object.fromEntries(Object.entries(entry).reverse());
    writeFileSync(path, `${JSON.stringify(reordered)}\n`);

    expect(verifyLedger(path).ok).toBe(true);
  });

  test("fails at the entry whose content was mutated", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));
    writer.append(body(3));

    const entries = readLedger(path);
    entries[1]!.test_result.status = "fail";
    writeFileSync(path, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`);

    const result = verifyLedger(path);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failedAtIndex).toBe(1);
    expect(result.ok === false && result.reason).toMatch(/hash/i);
  });

  test("fails at whichever entry was mutated, for every position in the chain", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));
    writer.append(body(3));
    writer.append(body(4));
    const original = readLedger(path);

    for (let index = 0; index < original.length; index++) {
      const mutated = readLedger(path);
      mutated[index]!.git_sha = "9".repeat(40);
      const mutatedPath = join(mkdtempSync(join(tmpdir(), "crossfire-ledger-")), "ledger.jsonl");
      writeFileSync(mutatedPath, `${mutated.map((entry) => JSON.stringify(entry)).join("\n")}\n`);

      const result = verifyLedger(mutatedPath);
      expect(result.ok).toBe(false);
      expect(result.ok === false && result.failedAtIndex).toBe(index);
    }

    expect(verifyLedger(path)).toEqual({ ok: true, entries: original.length });
  });

  test("fails at the entry whose recorded hash was rewritten", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));

    const entries = readLedger(path);
    entries[0]!.entry_hash = "f".repeat(64);
    writeFileSync(path, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`);

    const result = verifyLedger(path);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failedAtIndex).toBe(0);
  });

  test("fails where a removed entry breaks the link", () => {
    const path = ledgerPath();
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));
    writer.append(body(3));

    const entries = readLedger(path);
    entries.splice(1, 1);
    writeFileSync(path, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`);

    const result = verifyLedger(path);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failedAtIndex).toBe(1);
    expect(result.ok === false && result.reason).toMatch(/prev_hash|round/i);
  });

  test("fails on an appended entry that was never chained", () => {
    const path = ledgerPath();
    new LedgerWriter(path).append(body(1));
    appendFileSync(path, `${JSON.stringify({ ...body(2), prev_hash: GENESIS_HASH, entry_hash: "c".repeat(64) })}\n`);

    const result = verifyLedger(path);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failedAtIndex).toBe(1);
  });

  test("fails on a line that is not valid JSON", () => {
    const path = ledgerPath();
    new LedgerWriter(path).append(body(1));
    appendFileSync(path, "{ truncated\n");

    const result = verifyLedger(path);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failedAtIndex).toBe(1);
    expect(result.ok === false && result.reason).toMatch(/json/i);
  });

  test("fails on a line that does not match the entry schema", () => {
    const path = ledgerPath();
    new LedgerWriter(path).append(body(1));
    appendFileSync(path, `${JSON.stringify({ round: 2 })}\n`);

    const result = verifyLedger(path);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failedAtIndex).toBe(1);
  });

  test("verifies an empty ledger as an empty chain", () => {
    const path = ledgerPath();
    writeFileSync(path, "");

    expect(verifyLedger(path)).toEqual({ ok: true, entries: 0 });
  });
});
