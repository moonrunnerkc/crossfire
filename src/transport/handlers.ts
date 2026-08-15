import { readFileSync, writeFileSync } from "node:fs";

import type {
  ClientApp,
  PermissionOption,
  ReadTextFileRequest,
  RequestPermissionOutcome,
} from "@agentclientprotocol/sdk";
import { RequestError, methods } from "@agentclientprotocol/sdk";

import type { PermissionPolicy, PolicyDecision } from "../policy/index.js";
import { toolAccessOf } from "./events.js";

/**
 * JSON-RPC implementation-defined error code for a request the policy refused.
 * Agents see a hard error rather than an empty result, so a denial can never be
 * mistaken for "the file was empty" or "the write succeeded".
 */
export const ACCESS_DENIED = -32001;

export interface DeniedAccess {
  method: string;
  path: string;
  reason: string;
}

export interface HandlerHooks {
  /** Called for every refusal, so tests and obs/ can see what was blocked. */
  onDenied?: (denied: DeniedAccess) => void;
}

function deny(method: string, path: string, decision: PolicyDecision, hooks: HandlerHooks): never {
  hooks.onDenied?.({ method, path, reason: decision.reason });
  throw new RequestError(ACCESS_DENIED, `${method} denied: ${decision.reason}`);
}

function readSlice(path: string, params: ReadTextFileRequest): string {
  const content = readFileSync(path, "utf8");
  if (params.line === null || params.line === undefined) {
    return params.limit === null || params.limit === undefined
      ? content
      : content.split("\n").slice(0, params.limit).join("\n");
  }

  const lines = content.split("\n");
  const start = Math.max(0, params.line - 1);
  const end = params.limit === null || params.limit === undefined ? undefined : start + params.limit;
  return lines.slice(start, end).join("\n");
}

/**
 * Registers the client side of the protocol. Every path an agent asks for goes
 * through the policy first: this is where scoping is enforced, not in prompt
 * text, because an agent cannot be argued out of a handler that refuses.
 */
export function registerClientHandlers(
  app: ClientApp,
  policy: PermissionPolicy,
  hooks: HandlerHooks = {},
): ClientApp {
  return app
    .onRequest(methods.client.fs.readTextFile, (ctx) => {
      const decision = policy.readFile(ctx.params.path);
      if (!decision.allowed) {
        deny("fs/read_text_file", ctx.params.path, decision, hooks);
      }
      return { content: readSlice(ctx.params.path, ctx.params) };
    })
    .onRequest(methods.client.fs.writeTextFile, (ctx) => {
      const decision = policy.writeFile(ctx.params.path);
      if (!decision.allowed) {
        deny("fs/write_text_file", ctx.params.path, decision, hooks);
      }
      writeFileSync(ctx.params.path, ctx.params.content, "utf8");
      return {};
    })
    .onRequest(methods.client.session.requestPermission, (ctx) => {
      const { toolCall, options } = ctx.params;
      const decision = policy.toolCall({
        title: toolCall.title ?? toolCall.toolCallId,
        access: toolAccessOf(toolCall.kind),
        paths: (toolCall.locations ?? []).map((location) => location.path),
      });

      if (!decision.allowed) {
        hooks.onDenied?.({
          method: "session/request_permission",
          path: (toolCall.locations ?? []).map((location) => location.path).join(", "),
          reason: decision.reason,
        });
        return { outcome: refuse(options) };
      }
      return { outcome: approve(options) };
    });
}

/**
 * The broker decides once and never asks a human, so "always" options are never
 * selected: a standing grant would outlive the decision that justified it.
 */
function approve(options: readonly PermissionOption[]): RequestPermissionOutcome {
  const allow = options.find((option) => option.kind === "allow_once");
  return allow === undefined
    ? { outcome: "cancelled" }
    : { outcome: "selected", optionId: allow.optionId };
}

function refuse(options: readonly PermissionOption[]): RequestPermissionOutcome {
  const reject = options.find((option) => option.kind === "reject_once");
  return reject === undefined
    ? { outcome: "cancelled" }
    : { outcome: "selected", optionId: reject.optionId };
}
