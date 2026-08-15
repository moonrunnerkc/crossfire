import type { ContentBlock, SessionUpdate, ToolCallContent, ToolKind } from "@agentclientprotocol/sdk";

import type { AgentEvent } from "../contracts/index.js";
import { AgentEventSchema } from "../contracts/index.js";
import type { ToolAccess } from "../policy/index.js";

/** rawInput arrives as JSON over JSON-RPC and is re-validated by the schema. */
type ToolCallInput = Extract<AgentEvent, { type: "tool_call" }>["input"];

export class TransportError extends Error {
  constructor(message: string, options?: { cause: unknown }) {
    super(message, options);
    this.name = "TransportError";
  }
}

function textOf(content: ContentBlock): string | undefined {
  // Non-text blocks (images, audio, embedded resources) carry nothing the
  // broker acts on. They stay in the raw JSON-RPC transcript that obs/ records.
  return content.type === "text" ? content.text : undefined;
}

function toolOutput(content: ToolCallContent[] | null | undefined): string {
  if (content === null || content === undefined) {
    return "";
  }
  return content
    .map((item) => {
      switch (item.type) {
        case "content":
          return textOf(item.content) ?? `[${item.content.type}]`;
        case "diff":
          return `[diff ${item.path}]`;
        case "terminal":
          return `[terminal ${item.terminalId}]`;
        default:
          return "";
      }
    })
    .filter((part) => part.length > 0)
    .join("\n");
}

/**
 * Maps one ACP session update onto our event contract, or to undefined when the
 * update carries nothing the broker consumes (plans, mode changes, token usage).
 * Every event produced is validated, so a protocol violation halts the turn
 * instead of flowing into a prompt as something that looks usable.
 */
export function normalizeSessionUpdate(update: SessionUpdate): AgentEvent | undefined {
  const event = toEvent(update);
  if (event === undefined) {
    return undefined;
  }

  const parsed = AgentEventSchema.safeParse(event);
  if (!parsed.success) {
    throw new TransportError(
      `agent sent a ${update.sessionUpdate} that does not normalize to a valid event: ${parsed.error.issues[0]?.message ?? "unknown"}`,
      { cause: parsed.error },
    );
  }
  return parsed.data;
}

function toEvent(update: SessionUpdate): AgentEvent | undefined {
  switch (update.sessionUpdate) {
    case "agent_message_chunk": {
      const text = textOf(update.content);
      return text === undefined ? undefined : { type: "text", text };
    }
    case "agent_thought_chunk": {
      const text = textOf(update.content);
      return text === undefined ? undefined : { type: "thinking", text };
    }
    case "tool_call":
      return {
        type: "tool_call",
        call_id: update.toolCallId,
        name: update.name ?? update.title,
        input: (update.rawInput ?? {}) as ToolCallInput,
      };
    case "tool_call_update": {
      if (update.status !== "completed" && update.status !== "failed") {
        return undefined;
      }
      return {
        type: "tool_result",
        call_id: update.toolCallId,
        status: update.status === "completed" ? "ok" : "error",
        output: toolOutput(update.content),
      };
    }
    default:
      return undefined;
  }
}

const ACCESS_BY_TOOL_KIND: Record<string, ToolAccess> = {
  read: "read",
  search: "read",
  fetch: "read",
  edit: "write",
  delete: "write",
  move: "write",
  execute: "execute",
};

/** Translates an ACP tool call into the vocabulary the policy reasons about. */
export function toolAccessOf(kind: ToolKind | null | undefined): ToolAccess {
  return kind === null || kind === undefined ? "other" : (ACCESS_BY_TOOL_KIND[kind] ?? "other");
}
