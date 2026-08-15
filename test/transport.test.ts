import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import type { AgentEvent, AgentId } from "../src/contracts/index.js";
import { DEFAULT_EXCLUDED_PATHS } from "../src/config/index.js";
import { createPathScope, createPermissionPolicy } from "../src/policy/index.js";
import type { DeniedAccess } from "../src/transport/index.js";
import { AcpAgentHandle, normalizeSessionUpdate } from "../src/transport/index.js";
import type { AgentHandle } from "../src/transport/index.js";
import { createClaudeAgent, createGrokAgent } from "../src/adapters/index.js";

const FAKE_AGENT = resolve(import.meta.dirname, "..", "fixtures/fake-acp-agent.mjs");
const TURN_TIMEOUT_MS = 30_000;

const open: AgentHandle[] = [];

afterEach(async () => {
  await Promise.all(open.splice(0).map((handle) => handle.close()));
});

/** A target repo with the shapes the policy is supposed to care about. */
function makeRepo(): string {
  const repo = mkdtempSync(join(tmpdir(), "crossfire-repo-"));
  mkdirSync(join(repo, "src"), { recursive: true });
  mkdirSync(join(repo, "secrets"), { recursive: true });
  writeFileSync(join(repo, "src/app.c"), "int main(void) { return 0; }\n");
  writeFileSync(join(repo, ".env"), "API_KEY=super-secret\n");
  writeFileSync(join(repo, "secrets/token.txt"), "token\n");
  return repo;
}

function policyFor(agent: AgentId, repo: string) {
  return createPermissionPolicy(agent, createPathScope(repo, DEFAULT_EXCLUDED_PATHS));
}

async function connectFake(
  agent: AgentId,
  repo: string,
  onDenied?: (denied: DeniedAccess) => void,
): Promise<AgentHandle> {
  const handle = await AcpAgentHandle.connect({
    id: agent,
    command: process.execPath,
    args: [FAKE_AGENT],
    cwd: repo,
    policy: policyFor(agent, repo),
    ...(onDenied === undefined ? {} : { hooks: { onDenied } }),
  });
  open.push(handle);
  return handle;
}

async function collect(handle: AgentHandle, prompt: string): Promise<AgentEvent[]> {
  const events: AgentEvent[] = [];
  for await (const event of handle.prompt(prompt)) {
    events.push(event);
  }
  return events;
}

function textOf(events: readonly AgentEvent[]): string {
  return events
    .filter((event) => event.type === "text")
    .map((event) => event.text)
    .join("\n");
}

describe("ACP client wrapper against the fake agent", () => {
  test(
    "opens a session, streams a prompt turn, and finishes with a stop reason",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);

      const sessionId = await handle.newSession();
      expect(sessionId).toMatch(/^fake-session-\d+$/);

      const events = await collect(handle, "text hello from the fixture");

      expect(events).toEqual([
        { type: "text", text: "hello from the fixture" },
        { type: "done", stop_reason: "end_turn" },
      ]);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "normalizes thinking, tool calls, and tool results",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);
      await handle.newSession();

      const events = await collect(handle, "think weighing options\ntool ls");

      expect(events).toEqual([
        { type: "thinking", text: "weighing options" },
        { type: "tool_call", call_id: "call-1", name: "ls", input: { command: "ls" } },
        { type: "tool_result", call_id: "call-1", status: "ok", output: "ls finished" },
        { type: "done", stop_reason: "end_turn" },
      ]);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "drops updates the broker has no event for without stalling the turn",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);
      await handle.newSession();

      const events = await collect(handle, "noise\ntext still here");

      expect(events).toEqual([
        { type: "text", text: "still here" },
        { type: "done", stop_reason: "end_turn" },
      ]);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "cancel ends the turn as cancelled",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);
      await handle.newSession();

      const events: AgentEvent[] = [];
      for await (const event of handle.prompt("hang")) {
        events.push(event);
        if (event.type === "text") {
          await handle.cancel();
        }
      }

      expect(events.at(0)).toEqual({ type: "text", text: "working" });
      expect(events.at(-1)).toEqual({ type: "done", stop_reason: "cancelled" });
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "a prompt the agent rejects ends the stream with an error event",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);
      await handle.newSession();

      const events = await collect(handle, "fail the fixture said no");

      expect(events).toHaveLength(1);
      expect(events[0]?.type).toBe("error");
      expect(events[0]).toMatchObject({ message: expect.stringContaining("the fixture said no") });
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "prompting without a session is refused",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);

      await expect(collect(handle, "text hi")).rejects.toThrow(/no open session/);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "a second session replaces the first",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);

      const first = await handle.newSession();
      const second = await handle.newSession();

      expect(second).not.toBe(first);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "a command that cannot be spawned fails loudly",
    async () => {
      const repo = makeRepo();

      await expect(
        AcpAgentHandle.connect({
          id: "grok",
          command: "crossfire-no-such-agent-binary",
          args: [],
          cwd: repo,
          policy: policyFor("grok", repo),
        }),
      ).rejects.toThrow(/cannot start grok agent/);
    },
    TURN_TIMEOUT_MS,
  );
});

describe("session update normalization", () => {
  test("maps message and thought chunks", () => {
    expect(
      normalizeSessionUpdate({
        sessionUpdate: "agent_message_chunk",
        content: { type: "text", text: "hi" },
      }),
    ).toEqual({ type: "text", text: "hi" });

    expect(
      normalizeSessionUpdate({
        sessionUpdate: "agent_thought_chunk",
        content: { type: "text", text: "hmm" },
      }),
    ).toEqual({ type: "thinking", text: "hmm" });
  });

  test("ignores non-text content blocks and unconsumed update types", () => {
    expect(
      normalizeSessionUpdate({
        sessionUpdate: "agent_message_chunk",
        content: { type: "image", data: "AAAA", mimeType: "image/png" },
      }),
    ).toBeUndefined();

    expect(normalizeSessionUpdate({ sessionUpdate: "plan", entries: [] })).toBeUndefined();
  });

  test("emits a tool result only once the call reaches a terminal status", () => {
    expect(
      normalizeSessionUpdate({
        sessionUpdate: "tool_call_update",
        toolCallId: "c1",
        status: "in_progress",
      }),
    ).toBeUndefined();

    expect(
      normalizeSessionUpdate({
        sessionUpdate: "tool_call_update",
        toolCallId: "c1",
        status: "failed",
        content: [{ type: "content", content: { type: "text", text: "boom" } }],
      }),
    ).toEqual({ type: "tool_result", call_id: "c1", status: "error", output: "boom" });
  });

  test("falls back to the tool title when the agent sends no name", () => {
    expect(
      normalizeSessionUpdate({
        sessionUpdate: "tool_call",
        toolCallId: "c2",
        title: "Read file",
      }),
    ).toEqual({ type: "tool_call", call_id: "c2", name: "Read file", input: {} });
  });

  test("rejects an update that cannot make a valid event", () => {
    expect(() =>
      normalizeSessionUpdate({ sessionUpdate: "tool_call", toolCallId: "", title: "" }),
    ).toThrow(/does not normalize to a valid event/);
  });
});

describe("adapters", () => {
  test(
    "the Claude adapter opts into the subagent transcript capability",
    async () => {
      const repo = makeRepo();
      const handle = await createClaudeAgent({
        cwd: repo,
        policy: policyFor("claude", repo),
        command: process.execPath,
        args: [FAKE_AGENT],
      });
      open.push(handle);
      await handle.newSession();

      const advertised = textOf(await collect(handle, "caps"));

      // Deep equality would also pin whatever the SDK contributes on its own,
      // so this asserts the capabilities the adapter is responsible for.
      const capabilities = JSON.parse(advertised.replace(/^caps /, ""));
      expect(handle.id).toBe("claude");
      expect(handle.mode).toBe("acp");
      expect(capabilities.fs).toEqual({ readTextFile: true, writeTextFile: true });
      expect(capabilities.terminal).toBe(false);
      expect(capabilities._meta).toEqual({ "subagent-transcript": true });
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "the Grok adapter advertises filesystem access and no terminal",
    async () => {
      const repo = makeRepo();
      const handle = await createGrokAgent({
        cwd: repo,
        policy: policyFor("grok", repo),
        command: process.execPath,
        args: [FAKE_AGENT],
      });
      open.push(handle);
      await handle.newSession();

      const advertised = textOf(await collect(handle, "caps"));

      const capabilities = JSON.parse(advertised.replace(/^caps /, ""));
      expect(handle.id).toBe("grok");
      expect(capabilities.fs).toEqual({ readTextFile: true, writeTextFile: true });
      expect(capabilities.terminal).toBe(false);
      // Grok has no nested subagent transcript to opt into.
      expect(capabilities._meta).toBeUndefined();
    },
    TURN_TIMEOUT_MS,
  );
});

describe("policy enforced inside the client handlers", () => {
  test(
    "a Grok source write is denied at the handler",
    async () => {
      const repo = makeRepo();
      const denied: DeniedAccess[] = [];
      const handle = await connectFake("grok", repo, (entry) => denied.push(entry));
      await handle.newSession();

      const said = textOf(await collect(handle, `write ${join(repo, "src/app.c")}`));

      expect(said).toContain("write refused");
      expect(denied).toHaveLength(1);
      expect(denied[0]?.method).toBe("fs/write_text_file");
      expect(denied[0]?.reason).toContain("grok has no write access");
      // The file on disk is untouched, not merely reported as refused.
      expect(readFileSync(join(repo, "src/app.c"), "utf8")).toBe("int main(void) { return 0; }\n");
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "the same write from Claude is allowed and actually lands",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);
      await handle.newSession();

      const said = textOf(await collect(handle, `write ${join(repo, "src/app.c")}`));

      expect(said).toContain("write ok");
      expect(readFileSync(join(repo, "src/app.c"), "utf8")).toBe("written by the fake agent\n");
    },
    TURN_TIMEOUT_MS,
  );

  test.each(["claude", "grok"] as const)(
    "%s cannot read an excluded secret",
    async (agent) => {
      const repo = makeRepo();
      const denied: DeniedAccess[] = [];
      const handle = await connectFake(agent, repo, (entry) => denied.push(entry));
      await handle.newSession();

      const said = textOf(await collect(handle, `read ${join(repo, ".env")}`));

      expect(said).toContain("read refused");
      expect(denied[0]?.reason).toContain("excluded path");
    },
    TURN_TIMEOUT_MS,
  );

  test.each([
    ["a secrets directory", "secrets/token.txt"],
    ["a path escaping the repo", "../../../etc/passwd"],
  ])(
    "reading %s is denied",
    async (_label, path) => {
      const repo = makeRepo();
      const denied: DeniedAccess[] = [];
      const handle = await connectFake("claude", repo, (entry) => denied.push(entry));
      await handle.newSession();

      const said = textOf(await collect(handle, `read ${join(repo, path)}`));

      expect(said).toContain("read refused");
      expect(denied).toHaveLength(1);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "a permission request for an edit is refused for Grok and allowed for Claude",
    async () => {
      const repo = makeRepo();
      const source = join(repo, "src/app.c");

      const grok = await connectFake("grok", repo);
      await grok.newSession();
      expect(textOf(await collect(grok, `ask edit ${source}`))).toContain("permission: no");

      const claude = await connectFake("claude", repo);
      await claude.newSession();
      expect(textOf(await collect(claude, `ask edit ${source}`))).toContain("permission: yes");
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "Grok keeps read and execute permission",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("grok", repo);
      await handle.newSession();

      expect(textOf(await collect(handle, `ask read ${join(repo, "src/app.c")}`))).toContain(
        "permission: yes",
      );
      expect(textOf(await collect(handle, "ask execute"))).toContain("permission: yes");
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "a permission request naming an excluded path is refused whoever asks",
    async () => {
      const repo = makeRepo();
      const handle = await connectFake("claude", repo);
      await handle.newSession();

      expect(textOf(await collect(handle, `ask read ${join(repo, ".env")}`))).toContain(
        "permission: no",
      );
    },
    TURN_TIMEOUT_MS,
  );
});
