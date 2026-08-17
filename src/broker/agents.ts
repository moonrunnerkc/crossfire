import type { AgentId } from "../contracts/index.js";
import type { AgentHandle } from "../transport/index.js";
import { BrokerError } from "./errors.js";
import type { AgentRunner, AgentTurn } from "./state-machine.js";

/** Spawns an agent process and returns a handle to it, ready for one turn. */
export type AgentConnector = () => Promise<AgentHandle>;

/**
 * Drives a routed subtask through an agent and returns what it said.
 *
 * The turn already names its agent, decided by the router, and this runner only
 * looks that connector up: an agent that could pick its own work would be the
 * routing table with extra steps.
 *
 * Every turn gets its own process, opened here and closed before the turn
 * returns. Rule 7 says a call carries the current findings and the diff and
 * never an accumulated transcript, and a process that does not outlive its turn
 * is the only way to be sure of that rather than to hope for it. It also means
 * the broker never holds a connection it is not using: an agent connected at
 * run start sits idle through detection and every other agent's turns, and a
 * connection nothing is watching is one that can be gone by the time it is
 * needed, for reasons that are not the broker's to diagnose.
 */
export function createAgentRunner(
  connectors: Readonly<Partial<Record<AgentId, AgentConnector>>>,
): AgentRunner {
  return {
    async run(turn: AgentTurn): Promise<string> {
      const connect = connectors[turn.agent];
      if (connect === undefined) {
        throw new BrokerError(
          `the ${turn.subtask} subtask routes to ${turn.agent}, which this run has no connector for`,
        );
      }

      const handle = await connect();
      try {
        return await driveTurn(handle, turn);
      } finally {
        await handle.close();
      }
    },
  };
}

async function driveTurn(handle: AgentHandle, turn: AgentTurn): Promise<string> {
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
        throw new BrokerError(`the ${turn.agent} ${turn.subtask} turn failed: ${event.message}`);
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
}
