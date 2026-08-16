import type { AgentId } from "../contracts/index.js";
import type { AgentHandle } from "../transport/index.js";
import { BrokerError } from "./errors.js";
import type { AgentRunner, AgentTurn } from "./state-machine.js";

/**
 * Drives a routed subtask through a live agent and returns what it said.
 *
 * The turn already names its agent, decided by the router, and this runner only
 * looks that handle up: an agent that could pick its own work would be the
 * routing table with extra steps.
 *
 * Every turn opens a fresh session. Rule 7 says a call carries the current
 * findings and the diff and never an accumulated transcript, and a new session
 * is the only way to be sure of that rather than to hope for it.
 */
export function createAgentRunner(
  handles: Readonly<Partial<Record<AgentId, AgentHandle>>>,
): AgentRunner {
  return {
    async run(turn: AgentTurn): Promise<string> {
      const handle = handles[turn.agent];
      if (handle === undefined) {
        throw new BrokerError(
          `the ${turn.subtask} subtask routes to ${turn.agent}, which this run has no handle for`,
        );
      }

      await handle.newSession();

      const cancelTurn = (): void => {
        // The broker has already stopped waiting; this stops the agent burning
        // tokens on an answer nobody will read.
        void handle.cancel();
      };
      turn.signal.addEventListener("abort", cancelTurn, { once: true });

      const said: string[] = [];
      try {
        for await (const event of handle.prompt(turn.prompt)) {
          if (event.type === "text") {
            said.push(event.text);
            continue;
          }
          if (event.type === "error") {
            throw new BrokerError(
              `the ${turn.agent} ${turn.subtask} turn failed: ${event.message}`,
            );
          }
          if (event.type === "done" && event.stop_reason !== "end_turn") {
            throw new BrokerError(
              `the ${turn.agent} ${turn.subtask} turn ended as ${event.stop_reason}, so its answer is incomplete`,
            );
          }
        }
      } finally {
        turn.signal.removeEventListener("abort", cancelTurn);
      }

      const answer = said.join("");
      if (answer.trim() === "") {
        throw new BrokerError(`the ${turn.agent} ${turn.subtask} turn produced no text`);
      }
      return answer;
    },
  };
}
