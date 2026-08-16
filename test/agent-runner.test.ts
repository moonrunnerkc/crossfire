import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { z } from "zod";
import { afterEach, describe, expect, test } from "vitest";

import { DEFAULT_EXCLUDED_PATHS } from "../src/config/index.js";
import type { AgentEvent, AgentId } from "../src/contracts/index.js";
import { createPathScope, createPermissionPolicy } from "../src/policy/index.js";
import { AcpAgentHandle } from "../src/transport/index.js";
import type { AgentHandle } from "../src/transport/index.js";
import { BrokerError, createAgentRunner, parseAgentJson } from "../src/broker/index.js";

const FAKE_AGENT = resolve(import.meta.dirname, "..", "fixtures/fake-acp-agent.mjs");
const TURN_TIMEOUT_MS = 30_000;

const open: AgentHandle[] = [];

afterEach(async () => {
  await Promise.all(open.splice(0).map((handle) => handle.close()));
});

function makeRepo(): string {
  const repo = mkdtempSync(join(tmpdir(), "crossfire-runner-"));
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src/app.c"), "int main(void) { return 0; }\n");
  return repo;
}

async function connectFake(agent: AgentId): Promise<AgentHandle> {
  const repo = makeRepo();
  const handle = await AcpAgentHandle.connect({
    id: agent,
    command: process.execPath,
    args: [FAKE_AGENT],
    cwd: repo,
    policy: createPermissionPolicy(agent, createPathScope(repo, DEFAULT_EXCLUDED_PATHS)),
  });
  open.push(handle);
  return handle;
}

function neverAborts(): AbortSignal {
  return new AbortController().signal;
}

interface Recorded {
  handle: AgentHandle;
  prompts: string[];
  sessions: () => number;
}

/** An in-memory handle, for the assertions that are about the runner, not the wire. */
function recordingHandle(id: AgentId, answer: string): Recorded {
  const prompts: string[] = [];
  let sessions = 0;

  const handle: AgentHandle = {
    id,
    mode: "acp",
    newSession: () => {
      sessions += 1;
      return Promise.resolve(`session-${sessions}`);
    },
    prompt(text: string): AsyncIterable<AgentEvent> {
      prompts.push(text);
      return (async function* () {
        yield { type: "text", text: answer } satisfies AgentEvent;
        yield { type: "done", stop_reason: "end_turn" } satisfies AgentEvent;
      })();
    },
    cancel: () => Promise.resolve(),
    close: () => Promise.resolve(),
  };

  return { handle, prompts, sessions: () => sessions };
}

describe("the agent runner over a live ACP handle", () => {
  test(
    "returns what the agent said as one string",
    async () => {
      const runner = createAgentRunner({ claude: await connectFake("claude") });

      const answer = await runner.run({
        subtask: "fix",
        agent: "claude",
        round: 1,
        prompt: `text {"round": 1}`,
        signal: neverAborts(),
      });

      expect(answer.trim()).toBe(`{"round": 1}`);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "a turn that says nothing halts rather than returning an empty answer",
    async () => {
      const runner = createAgentRunner({ grok: await connectFake("grok") });

      await expect(
        runner.run({
          subtask: "crash-analysis",
          agent: "grok",
          round: 1,
          // Streams updates the broker has no event for, so no text arrives.
          prompt: "noise",
          signal: neverAborts(),
        }),
      ).rejects.toThrow(/no text/);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "a turn the agent refuses halts the round",
    async () => {
      const runner = createAgentRunner({ grok: await connectFake("grok") });

      await expect(
        runner.run({
          subtask: "candidate-confirmation",
          agent: "grok",
          round: 1,
          prompt: "fail the model is unavailable",
          signal: neverAborts(),
        }),
      ).rejects.toThrow(BrokerError);
    },
    TURN_TIMEOUT_MS,
  );

  test(
    "an aborted turn is cancelled at the agent and reported, not half returned",
    async () => {
      const runner = createAgentRunner({ claude: await connectFake("claude") });
      const controller = new AbortController();
      setTimeout(() => {
        controller.abort();
      }, 250);

      await expect(
        runner.run({
          subtask: "fix",
          agent: "claude",
          round: 1,
          prompt: "text partial answer\nhang",
          signal: controller.signal,
        }),
      ).rejects.toThrow(/cancelled/);
    },
    TURN_TIMEOUT_MS,
  );
});

describe("the agent runner picking a handle", () => {
  test("sends the turn to the agent the router named", async () => {
    const claude = recordingHandle("claude", "{}");
    const grok = recordingHandle("grok", "{}");
    const runner = createAgentRunner({ claude: claude.handle, grok: grok.handle });

    await runner.run({
      subtask: "crash-analysis",
      agent: "grok",
      round: 1,
      prompt: "analyze this",
      signal: neverAborts(),
    });

    expect(grok.prompts).toEqual(["analyze this"]);
    expect(claude.prompts).toEqual([]);
  });

  test("refuses a turn for an agent it was never given", async () => {
    const runner = createAgentRunner({ claude: recordingHandle("claude", "{}").handle });

    await expect(
      runner.run({
        subtask: "crash-analysis",
        agent: "grok",
        round: 1,
        prompt: "analyze this",
        signal: neverAborts(),
      }),
    ).rejects.toThrow(/grok/);
  });

  test("opens a fresh session per turn so no transcript accumulates", async () => {
    const claude = recordingHandle("claude", "{}");
    const runner = createAgentRunner({ claude: claude.handle, grok: recordingHandle("grok", "{}").handle });

    for (const prompt of ["first", "second", "third"]) {
      await runner.run({ subtask: "fix", agent: "claude", round: 1, prompt, signal: neverAborts() });
    }

    expect(claude.sessions()).toBe(3);
    expect(claude.prompts).toEqual(["first", "second", "third"]);
  });
});

describe("parsing an agent answer", () => {
  const Schema = z.strictObject({ status: z.string(), count: z.number() });

  test("takes a bare JSON object", () => {
    expect(parseAgentJson(Schema, `{"status": "ok", "count": 2}`, "fix")).toEqual({
      status: "ok",
      count: 2,
    });
  });

  test("takes a JSON object inside a fenced block", () => {
    const text = '```json\n{"status": "ok", "count": 2}\n```';

    expect(parseAgentJson(Schema, text, "fix")).toEqual({ status: "ok", count: 2 });
  });

  test("takes a fenced block an agent wrapped in prose", () => {
    // Real agents preface an answer. A delimited block is unambiguous, so
    // reading it is transport rather than a guess at what was meant.
    const text = [
      "I read the crash and here is the analysis.",
      "```json",
      '{"status": "ok", "count": 2}',
      "```",
      "Let me know if you want more detail.",
    ].join("\n");

    expect(parseAgentJson(Schema, text, "fix")).toEqual({ status: "ok", count: 2 });
  });

  test("takes the answer an agent settled on, not the one it showed on the way", () => {
    const text = [
      "First I thought the shape was:",
      '```json\n{"status": "draft", "count": 1}\n```',
      "but after running the repro it is:",
      '```json\n{"status": "ok", "count": 2}\n```',
    ].join("\n");

    expect(parseAgentJson(Schema, text, "fix")).toEqual({ status: "ok", count: 2 });
  });

  test("refuses a final answer that misses the schema even when an earlier one would pass", () => {
    // Substituting the earlier object would act on a verdict the agent revised.
    const text = [
      '```json\n{"status": "ok", "count": 1}\n```',
      "Correction, the count is not known:",
      '```json\n{"status": "ok"}\n```',
    ].join("\n");

    expect(() => parseAgentJson(Schema, text, "fix")).toThrow(/schema rejected/);
  });

  test("ignores a brace that is only prose", () => {
    const text = 'The rule matches strcpy($DST, $SRC) inside { } blocks.\n{"status": "ok", "count": 1}';

    expect(parseAgentJson(Schema, text, "fix")).toEqual({ status: "ok", count: 1 });
  });

  test("reports what arrived when an agent narrates instead of answering", () => {
    expect(() =>
      parseAgentJson(Schema, "I'll inspect the parser and get back to you.", "candidate-confirmation"),
    ).toThrow(/I'll inspect the parser/);
  });

  test("refuses prose with no JSON in it", () => {
    expect(() => parseAgentJson(Schema, "It looks fine to me.", "fix")).toThrow(BrokerError);
  });

  test("refuses JSON the schema rejects, naming the subtask", () => {
    expect(() => parseAgentJson(Schema, `{"status": "ok"}`, "crash-analysis")).toThrow(
      /crash-analysis/,
    );
  });
});
