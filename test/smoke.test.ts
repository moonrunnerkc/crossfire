import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import { DEFAULT_EXCLUDED_PATHS } from "../src/config/index.js";
import type { AgentEvent, AgentId } from "../src/contracts/index.js";
import { AgentEventSchema } from "../src/contracts/index.js";
import { createClaudeAgent, createGrokAgent } from "../src/adapters/index.js";
import { createPathScope, createPermissionPolicy } from "../src/policy/index.js";
import type { AgentHandle } from "../src/transport/index.js";

/**
 * Off by default: these spawn the real agents, spend real tokens, and need the
 * machine to be logged in. Run them with CROSSFIRE_SMOKE=1 npm test.
 */
const SMOKE = process.env.CROSSFIRE_SMOKE === "1";
const SMOKE_TIMEOUT_MS = 180_000;

function makeRepo(): string {
  const repo = mkdtempSync(join(tmpdir(), "crossfire-smoke-"));
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src/app.c"), "int main(void) { return 0; }\n");
  writeFileSync(join(repo, ".env"), "API_KEY=must-never-be-read\n");
  return repo;
}

function policyFor(agent: AgentId, repo: string) {
  return createPermissionPolicy(agent, createPathScope(repo, DEFAULT_EXCLUDED_PATHS));
}

async function askForAWord(handle: AgentHandle): Promise<AgentEvent[]> {
  await handle.newSession();
  const events: AgentEvent[] = [];
  for await (const event of handle.prompt("Reply with exactly the word: ready")) {
    events.push(event);
  }
  return events;
}

function assertWellFormed(events: readonly AgentEvent[]): void {
  // Every event holds up against the contract, not just the ones we assert on.
  for (const event of events) {
    expect(AgentEventSchema.safeParse(event).success).toBe(true);
  }

  const last = events.at(-1);
  expect(last?.type).toBe("done");

  const said = events
    .filter((event) => event.type === "text")
    .map((event) => event.text)
    .join(" ")
    .toLowerCase();
  expect(said).toContain("ready");
}

describe.runIf(SMOKE)("smoke tests against the real agents", () => {
  test(
    "Claude answers a trivial prompt over ACP",
    async () => {
      const repo = makeRepo();
      const handle = await createClaudeAgent({ cwd: repo, policy: policyFor("claude", repo) });
      try {
        expect(handle.mode).toBe("acp");
        assertWellFormed(await askForAWord(handle));
      } finally {
        await handle.close();
      }
    },
    SMOKE_TIMEOUT_MS,
  );

  test(
    "Grok answers a trivial prompt over native ACP",
    async () => {
      const repo = makeRepo();
      const handle = await createGrokAgent({ cwd: repo, policy: policyFor("grok", repo) });
      try {
        expect(handle.mode).toBe("acp");
        assertWellFormed(await askForAWord(handle));
      } finally {
        await handle.close();
      }
    },
    SMOKE_TIMEOUT_MS,
  );
});
