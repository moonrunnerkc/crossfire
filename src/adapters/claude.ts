import { fileURLToPath } from "node:url";

import type { PermissionPolicy } from "../policy/index.js";
import type { HandlerHooks } from "../transport/index.js";
import { AcpAgentHandle, TransportError } from "../transport/index.js";
import type { AgentHandle } from "../transport/index.js";

/**
 * Claude reports nested subagent activity only when the client asks for it.
 * Without this the broker sees a single opaque tool call where a subagent ran,
 * which would leave part of a fix round unobservable.
 */
const SUBAGENT_TRANSCRIPT = "subagent-transcript";

const ADAPTER_ENTRY = "@agentclientprotocol/claude-agent-acp/dist/index.js";

export interface ClaudeAdapterOptions {
  cwd: string;
  policy: PermissionPolicy;
  /** Overrides the resolved adapter entry point, for tests and odd installs. */
  command?: string;
  args?: readonly string[];
  env?: NodeJS.ProcessEnv;
  hooks?: HandlerHooks;
}

function resolveAdapterEntry(): string {
  try {
    return fileURLToPath(import.meta.resolve(ADAPTER_ENTRY));
  } catch (error) {
    throw new TransportError(
      `cannot resolve ${ADAPTER_ENTRY}, is @agentclientprotocol/claude-agent-acp installed?`,
      { cause: error },
    );
  }
}

/**
 * Spawns Claude Code through the official ACP adapter. The adapter is run with
 * the Node binary already running the broker rather than through a shim on
 * PATH, so which Claude answers does not depend on the caller's shell.
 */
export function createClaudeAgent(options: ClaudeAdapterOptions): Promise<AgentHandle> {
  const command = options.command ?? process.execPath;
  const args = options.args ?? [resolveAdapterEntry()];

  return AcpAgentHandle.connect({
    id: "claude",
    command,
    args,
    cwd: options.cwd,
    policy: options.policy,
    capabilityMeta: { [SUBAGENT_TRANSCRIPT]: true },
    ...(options.env === undefined ? {} : { env: options.env }),
    ...(options.hooks === undefined ? {} : { hooks: options.hooks }),
  });
}
