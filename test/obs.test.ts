import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { DEFAULT_EXCLUDED_PATHS } from "../src/config/index.js";
import type { LedgerEntryBody } from "../src/contracts/index.js";
import { LedgerWriter } from "../src/ledger/index.js";
import { createPathScope, createPermissionPolicy } from "../src/policy/index.js";
import { AcpAgentHandle } from "../src/transport/index.js";
import type { AgentHandle } from "../src/transport/index.js";
import { exportLedger, openRunLog, openTranscript } from "../src/obs/index.js";

const FAKE_AGENT = resolve(import.meta.dirname, "..", "fixtures/fake-acp-agent.mjs");
const TURN_TIMEOUT_MS = 30_000;

const open: AgentHandle[] = [];

afterEach(async () => {
  await Promise.all(open.splice(0).map((handle) => handle.close()));
});

function runDir(): string {
  return mkdtempSync(join(tmpdir(), "crossfire-obs-"));
}

function makeRepo(): string {
  const repo = mkdtempSync(join(tmpdir(), "crossfire-obs-repo-"));
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src/app.c"), "int main(void) { return 0; }\n");
  writeFileSync(join(repo, ".env"), "API_KEY=must-never-be-read\n");
  return repo;
}

function lines(path: string): Record<string, unknown>[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function body(round: number): LedgerEntryBody {
  return {
    round,
    started_at: "2026-08-15T10:00:00.000Z",
    ended_at: "2026-08-15T10:04:30.000Z",
    detector_runs: [{ detector: "fuzz", status: "ok", duration_ms: 10, findings_emitted: 1 }],
    findings_hash: "a".repeat(64),
    fixes_hash: "b".repeat(64),
    verify_results: [
      { finding_id: "fuzz-1", outcome: "closed", exit_code: 1, duration_ms: 5 },
    ],
    test_result: { status: "pass", command: "npm test", exit_code: 0, duration_ms: 20 },
    git_sha: "0".repeat(40),
  };
}

describe("per agent transcripts", () => {
  test(
    "records both directions of the JSON-RPC conversation",
    async () => {
      const dir = runDir();
      const path = join(dir, "grok.jsonl");
      const transcript = openTranscript(path);
      const repo = makeRepo();

      const handle = await AcpAgentHandle.connect({
        id: "grok",
        command: process.execPath,
        args: [FAKE_AGENT],
        cwd: repo,
        policy: createPermissionPolicy("grok", createPathScope(repo, DEFAULT_EXCLUDED_PATHS)),
        hooks: transcript.hooks,
      });
      open.push(handle);
      await handle.newSession();
      // Drained so the turn completes; the transcript is what is under test.
      for await (const event of handle.prompt("text hello")) {
        expect(event.type).toBeDefined();
      }
      transcript.close();

      const recorded = lines(path);
      const outbound = recorded.filter((entry) => entry.direction === "out");
      const inbound = recorded.filter((entry) => entry.direction === "in");
      expect(outbound.length).toBeGreaterThan(0);
      expect(inbound.length).toBeGreaterThan(0);

      // Replayable: the initialize handshake and the prompt turn are both in it,
      // as the messages that actually crossed the wire.
      const methods = recorded.map((entry) => (entry.message as { method?: string }).method);
      expect(methods).toContain("initialize");
      expect(methods).toContain("session/prompt");
      expect(recorded.every((entry) => typeof entry.ts === "string")).toBe(true);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "records what the policy refused alongside the traffic",
    async () => {
      const dir = runDir();
      const path = join(dir, "grok.jsonl");
      const transcript = openTranscript(path);
      const repo = makeRepo();

      const handle = await AcpAgentHandle.connect({
        id: "grok",
        command: process.execPath,
        args: [FAKE_AGENT],
        cwd: repo,
        policy: createPermissionPolicy("grok", createPathScope(repo, DEFAULT_EXCLUDED_PATHS)),
        hooks: transcript.hooks,
      });
      open.push(handle);
      await handle.newSession();
      for await (const event of handle.prompt("read .env")) {
        expect(event.type).toBeDefined();
      }
      transcript.close();

      const denied = lines(path).filter((entry) => entry.kind === "denied");
      expect(denied).toHaveLength(1);
      expect(denied[0]).toMatchObject({ path: ".env" });
    },
    TURN_TIMEOUT_MS,
  );
});

describe("the structured run log", () => {
  test("appends one JSON line per event, in order", () => {
    const path = join(runDir(), "run.jsonl");
    const log = openRunLog(path);

    log.write({ type: "round-started", round: 1 });
    log.write({ type: "tested", round: 1, result: body(1).test_result, regressed: false });
    log.write({ type: "terminated", reason: "clean", rounds: 1 });
    log.close();

    expect(lines(path).map((entry) => entry.type)).toEqual([
      "round-started",
      "tested",
      "terminated",
    ]);
    expect(lines(path).every((entry) => typeof entry.ts === "string")).toBe(true);
  });
});

describe("the ledger export", () => {
  test("carries every entry and its own verification", () => {
    const path = join(runDir(), "ledger.jsonl");
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));

    const exported = exportLedger(path);

    expect(exported.verification).toEqual({ ok: true, entries: 2 });
    expect(exported.entries.map((entry) => entry.round)).toEqual([1, 2]);
    expect(exported.entries[1]?.prev_hash).toBe(exported.entries[0]?.entry_hash);
  });

  test("reports a tampered chain rather than exporting it as sound", () => {
    const path = join(runDir(), "ledger.jsonl");
    const writer = new LedgerWriter(path);
    writer.append(body(1));
    writer.append(body(2));

    const entries = readFileSync(path, "utf8").split("\n").filter((line) => line.length > 0);
    const forged = JSON.parse(entries[0]!) as Record<string, unknown>;
    forged.git_sha = "1".repeat(40);
    writeFileSync(path, [JSON.stringify(forged), entries[1]].join("\n"));

    const exported = exportLedger(path);

    expect(exported.verification.ok).toBe(false);
    expect(exported.entries).toEqual([]);
  });
});
