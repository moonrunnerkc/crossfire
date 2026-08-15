import type { AgentEvent, AgentId } from "../contracts/index.js";

/**
 * Native ACP over stdio, or a degraded path an adapter falls back to. Recorded
 * so a run can say which surface produced its results.
 */
export type TransportMode = "acp" | "headless";

export interface NewSessionOptions {
  /** Defaults to the handle's configured cwd. */
  cwd?: string;
}

/**
 * The uniform surface the broker drives an agent through. Adapters differ in
 * how they launch and what they advertise, never in this shape.
 *
 * Calls are stateless from our side: the broker opens a session, sends one
 * prompt carrying the current findings and diff, and reads the turn out. It
 * never replays an accumulated transcript.
 */
export interface AgentHandle {
  readonly id: AgentId;
  readonly mode: TransportMode;
  /** Opens a session, replacing any session already open. Returns its id. */
  newSession(options?: NewSessionOptions): Promise<string>;
  /** Streams one prompt turn. Ends with a done event, or an error event. */
  prompt(text: string): AsyncIterable<AgentEvent>;
  /** Asks the agent to stop the current turn. The turn ends as cancelled. */
  cancel(): Promise<void>;
  /** Shuts the agent down and releases the subprocess. */
  close(): Promise<void>;
}
