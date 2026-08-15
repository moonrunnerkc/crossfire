import type { AgentId } from "../contracts/index.js";
import type { PathScope } from "./exclusions.js";

export const TOOL_ACCESS = ["read", "write", "execute", "other"] as const;

export type ToolAccess = (typeof TOOL_ACCESS)[number];

export interface ToolRequest {
  title: string;
  access: ToolAccess;
  /** Paths the tool call says it will touch, empty when it names none. */
  paths: readonly string[];
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
}

export interface PermissionPolicy {
  readonly agent: AgentId;
  readFile(path: string): PolicyDecision;
  writeFile(path: string): PolicyDecision;
  toolCall(request: ToolRequest): PolicyDecision;
}

/**
 * Grok reasons over confirmed signals and runs things to prove them; it never
 * writes source. Claude is the only agent that patches. CLAUDE.md rule 6, and
 * the reason this is a table rather than prompt text is that prompt text is not
 * enforcement.
 */
const MAY_WRITE: Record<AgentId, boolean> = {
  claude: true,
  grok: false,
};

export function createPermissionPolicy(agent: AgentId, scope: PathScope): PermissionPolicy {
  function pathsAllowed(paths: readonly string[]): PolicyDecision | undefined {
    for (const path of paths) {
      const decision = scope.check(path);
      if (!decision.allowed) {
        return { allowed: false, reason: decision.reason };
      }
    }
    return undefined;
  }

  return {
    agent,

    readFile(path: string): PolicyDecision {
      const decision = scope.check(path);
      return { allowed: decision.allowed, reason: decision.reason };
    },

    writeFile(path: string): PolicyDecision {
      if (!MAY_WRITE[agent]) {
        return { allowed: false, reason: `${agent} has no write access` };
      }
      const decision = scope.check(path);
      return { allowed: decision.allowed, reason: decision.reason };
    },

    toolCall(request: ToolRequest): PolicyDecision {
      const outOfScope = pathsAllowed(request.paths);
      if (outOfScope !== undefined) {
        return outOfScope;
      }
      if (request.access === "write" && !MAY_WRITE[agent]) {
        return { allowed: false, reason: `${agent} may not run write tools (${request.title})` };
      }
      return { allowed: true, reason: "permitted by policy" };
    },
  };
}
