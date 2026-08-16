import type { AgentId } from "../contracts/index.js";

/**
 * Every kind of work the broker hands to an agent. Detection is deliberately
 * absent: fuzzers and scanners find the bugs, and a class for that here would be
 * an invitation to let a model do the finding.
 */
export const SUBTASK_CLASSES = [
  "crash-analysis",
  "candidate-confirmation",
  "repro-authoring",
  "exploitability-assessment",
  "cold-hunt",
  "fix-planning",
  "fix",
  "refactor",
  "test-repair",
] as const;

export type SubtaskClass = (typeof SUBTASK_CLASSES)[number];

/**
 * Static by design. Which agent gets a subtask is a property of the subtask, not
 * a judgement call made per round, and never something a model is asked.
 *
 * Grok reasons over what the detectors found and proves it by building repros.
 * Claude writes the code. This split is also the reason Grok holds no write
 * access at the permission layer.
 */
export const ROUTING_TABLE: Readonly<Record<SubtaskClass, AgentId>> = {
  "crash-analysis": "grok",
  "candidate-confirmation": "grok",
  "repro-authoring": "grok",
  "exploitability-assessment": "grok",
  // Both are off by default. A cold-hunt raise is a candidate like any other and
  // buys its way in with a repro; the planner only writes prose for a prompt.
  "cold-hunt": "grok",
  "fix-planning": "grok",
  fix: "claude",
  refactor: "claude",
  "test-repair": "claude",
};

export class RoutingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RoutingError";
  }
}

/**
 * Fails closed on anything not in the table. A subtask class that arrives from
 * outside the compiler's reach, or one someone added without a route, must stop
 * the round rather than land on a default agent.
 */
export function routeSubtask(subtaskClass: SubtaskClass): AgentId {
  if (!Object.hasOwn(ROUTING_TABLE, subtaskClass)) {
    throw new RoutingError(
      `unknown subtask class: ${JSON.stringify(subtaskClass)}. Routable classes are ${SUBTASK_CLASSES.join(", ")}`,
    );
  }
  return ROUTING_TABLE[subtaskClass];
}
