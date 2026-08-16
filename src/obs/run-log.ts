import type { RunEvent } from "../broker/index.js";
import { openJsonl } from "./jsonl.js";

export interface RunLog {
  readonly path: string;
  write(event: RunEvent): void;
  close(): void;
}

/**
 * The structured record of a run: one line per phase, including what the
 * detectors produced, which agent took which turn and for how long, and how
 * every finding was judged. The ledger is the evidence; this is the narrative
 * that explains it, and nothing in the loop reads it back.
 */
export function openRunLog(path: string): RunLog {
  const log = openJsonl(path);

  return {
    path: log.path,
    write(event: RunEvent): void {
      log.write({ ...event });
    },
    close(): void {
      log.close();
    },
  };
}
