import type { PermissionPolicy } from "../policy/index.js";
import type { AgentHandle, HandlerHooks } from "../transport/index.js";
import { AcpAgentHandle } from "../transport/index.js";

/**
 * Confirmed from `grok --help` and `grok agent --help` on Grok Build 1.0.4:
 * `grok agent stdio` is documented as "Run the agent over stdio" and answers
 * initialize with protocolVersion 1, so the native ACP surface is what we
 * drive. The headless `grok -p` fallback the plan allows for is not built,
 * because building an unused degraded path would be dead code the next
 * maintainer has to keep honest.
 */
export const GROK_ACP_ARGS = ["agent", "stdio"] as const;

export interface GrokAdapterOptions {
  cwd: string;
  policy: PermissionPolicy;
  command?: string;
  args?: readonly string[];
  env?: NodeJS.ProcessEnv;
  hooks?: HandlerHooks;
}

/**
 * Spawns Grok Build as a native ACP agent. The policy handed in is what stops
 * it writing source; nothing in the launch invocation grants or removes that.
 */
export function createGrokAgent(options: GrokAdapterOptions): Promise<AgentHandle> {
  return AcpAgentHandle.connect({
    id: "grok",
    command: options.command ?? "grok",
    args: options.args ?? GROK_ACP_ARGS,
    cwd: options.cwd,
    policy: options.policy,
    ...(options.env === undefined ? {} : { env: options.env }),
    ...(options.hooks === undefined ? {} : { hooks: options.hooks }),
  });
}
