import type { HandlerHooks } from "../transport/index.js";
import { openJsonl } from "./jsonl.js";

export interface Transcript {
  readonly path: string;
  /** Pass to the adapter that spawns the agent. */
  readonly hooks: HandlerHooks;
  close(): void;
}

/**
 * One file per agent holding both directions of its JSON-RPC conversation, plus
 * every refusal the policy made. Together those are the whole of what the broker
 * and that agent said to each other, which is what makes a turn replayable after
 * the fact rather than something you have to take on trust.
 */
export function openTranscript(path: string): Transcript {
  const log = openJsonl(path);

  return {
    path: log.path,

    hooks: {
      onTraffic({ direction, line }) {
        // Parsed when it is JSON, which it always is on a healthy connection.
        // A line that is not gets recorded raw rather than dropped, since that
        // is exactly the case someone will be reading the transcript to explain.
        let message: unknown;
        try {
          message = JSON.parse(line);
        } catch {
          log.write({ kind: "rpc", direction, raw: line });
          return;
        }
        log.write({ kind: "rpc", direction, message });
      },

      onDenied({ method, path: denied, reason }) {
        log.write({ kind: "denied", method, path: denied, reason });
      },
    },

    close(): void {
      log.close();
    },
  };
}
