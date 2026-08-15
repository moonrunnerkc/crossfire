#!/usr/bin/env node
// A deterministic ACP agent for driving the transport wrapper without a model.
//
// The prompt text is a directive list, one per line, so a test can ask for
// exactly the traffic it wants to see:
//
//   text <words>        stream an agent_message_chunk
//   think <words>       stream an agent_thought_chunk
//   tool <name>         stream a tool_call then a completed tool_call_update
//   noise               stream updates the broker has no event for
//   caps                report the client capabilities seen at initialize
//   read <path>         call fs/read_text_file and report the result
//   write <path>        call fs/write_text_file and report the result
//   ask <kind> [path]   call session/request_permission and report the outcome
//   hang                stream one chunk, then wait to be cancelled
//   fail <message>      reject the session/prompt request
import { Readable, Writable } from "node:stream";

import * as acp from "@agentclientprotocol/sdk";

let clientCapabilities = null;
let nextSessionId = 0;
let nextToolCallId = 0;
const cancelled = new Set();

function report(text) {
  return { sessionUpdate: "agent_message_chunk", content: { type: "text", text } };
}

async function runDirective(ctx, sessionId, line) {
  const [verb, ...rest] = line.trim().split(" ");
  const argument = rest.join(" ");
  const send = (update) =>
    ctx.client.notify(acp.methods.client.session.update, { sessionId, update });

  switch (verb) {
    case "text":
      return send(report(argument));

    case "think":
      return send({
        sessionUpdate: "agent_thought_chunk",
        content: { type: "text", text: argument },
      });

    case "caps":
      return send(report(`caps ${JSON.stringify(clientCapabilities)}`));

    case "tool": {
      const toolCallId = `call-${(nextToolCallId += 1)}`;
      await send({
        sessionUpdate: "tool_call",
        toolCallId,
        title: `run ${argument}`,
        name: argument,
        kind: "execute",
        status: "pending",
        rawInput: { command: argument },
      });
      return send({
        sessionUpdate: "tool_call_update",
        toolCallId,
        status: "completed",
        content: [{ type: "content", content: { type: "text", text: `${argument} finished` } }],
      });
    }

    case "noise":
      // Updates the broker consumes no event for. They must not reach it, and
      // must not stall the turn either.
      await send({ sessionUpdate: "user_message_chunk", content: { type: "text", text: "echo" } });
      return send({ sessionUpdate: "plan", entries: [] });

    case "read":
      try {
        const result = await ctx.client.request(acp.methods.client.fs.readTextFile, {
          sessionId,
          path: argument,
        });
        return await send(report(`read ok: ${result.content.length} bytes`));
      } catch (error) {
        return await send(report(`read refused: ${error.message}`));
      }

    case "write":
      try {
        await ctx.client.request(acp.methods.client.fs.writeTextFile, {
          sessionId,
          path: argument,
          content: "written by the fake agent\n",
        });
        return await send(report("write ok"));
      } catch (error) {
        return await send(report(`write refused: ${error.message}`));
      }

    case "ask": {
      const [kind, ...pathParts] = rest;
      const path = pathParts.join(" ");
      const result = await ctx.client.request(acp.methods.client.session.requestPermission, {
        sessionId,
        toolCall: {
          toolCallId: `perm-${(nextToolCallId += 1)}`,
          title: `${kind} something`,
          kind,
          locations: path.length > 0 ? [{ path }] : [],
        },
        options: [
          { optionId: "yes", name: "Allow once", kind: "allow_once" },
          { optionId: "no", name: "Reject once", kind: "reject_once" },
        ],
      });
      const outcome =
        result.outcome.outcome === "selected" ? result.outcome.optionId : result.outcome.outcome;
      return send(report(`permission: ${outcome}`));
    }

    case "hang":
      await send(report("working"));
      while (!cancelled.has(sessionId)) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      return undefined;

    case "fail":
      throw new acp.RequestError(-32000, argument.length > 0 ? argument : "the fake agent refused");

    default:
      return send(report(`unknown directive: ${verb}`));
  }
}

const stream = acp.ndJsonStream(
  Writable.toWeb(process.stdout),
  Readable.toWeb(process.stdin),
);

const connection = acp
  .agent({ name: "fake-acp-agent" })
  .onRequest(acp.methods.agent.initialize, (ctx) => {
    clientCapabilities = ctx.params.clientCapabilities ?? null;
    return {
      protocolVersion: acp.PROTOCOL_VERSION,
      agentCapabilities: { loadSession: false },
    };
  })
  .onRequest(acp.methods.agent.session.new, () => ({
    sessionId: `fake-session-${(nextSessionId += 1)}`,
  }))
  .onNotification(acp.methods.agent.session.cancel, (ctx) => {
    cancelled.add(ctx.params.sessionId);
  })
  .onRequest(acp.methods.agent.session.prompt, async (ctx) => {
    const { sessionId, prompt } = ctx.params;
    cancelled.delete(sessionId);

    const text = prompt
      .filter((block) => block.type === "text")
      .map((block) => block.text)
      .join("\n");

    for (const line of text.split("\n")) {
      if (line.trim().length === 0) {
        continue;
      }
      if (cancelled.has(sessionId)) {
        break;
      }
      await runDirective(ctx, sessionId, line);
    }

    return { stopReason: cancelled.has(sessionId) ? "cancelled" : "end_turn" };
  })
  .connect(stream);

await connection.closed;
