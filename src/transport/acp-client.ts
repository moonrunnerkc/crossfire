import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { spawn } from "node:child_process";
import { Readable, Writable } from "node:stream";

import type {
  ActiveSession,
  ClientCapabilities,
  ClientConnection,
} from "@agentclientprotocol/sdk";
import { PROTOCOL_VERSION, client, methods, ndJsonStream } from "@agentclientprotocol/sdk";

import type { AgentEvent, AgentId } from "../contracts/index.js";
import type { PermissionPolicy } from "../policy/index.js";
import { TransportError, normalizeSessionUpdate } from "./events.js";
import type { HandlerHooks } from "./handlers.js";
import { registerClientHandlers } from "./handlers.js";
import type { AgentHandle, NewSessionOptions, TransportMode } from "./types.js";

/** Kept so a spawn that dies on startup reports why instead of "closed". */
const STDERR_TAIL_BYTES = 4_000;

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export interface AcpClientConfig {
  id: AgentId;
  command: string;
  args: readonly string[];
  cwd: string;
  policy: PermissionPolicy;
  env?: NodeJS.ProcessEnv;
  /** Merged into clientCapabilities._meta during initialize. */
  capabilityMeta?: Record<string, unknown>;
  hooks?: HandlerHooks;
}

/**
 * An agent running as an ACP subprocess over stdio.
 *
 * The client advertises filesystem access and no terminal: agents run their own
 * tools and ask through session/request_permission, and the broker runs every
 * verification command itself rather than lending out a shell.
 */
export class AcpAgentHandle implements AgentHandle {
  readonly id: AgentId;
  readonly mode: TransportMode = "acp";

  private readonly child: ChildProcessWithoutNullStreams;
  private readonly connection: ClientConnection;
  private readonly cwd: string;
  private stderrTail = "";
  private session: ActiveSession | undefined;
  private closed = false;

  private constructor(
    id: AgentId,
    child: ChildProcessWithoutNullStreams,
    connection: ClientConnection,
    cwd: string,
  ) {
    this.id = id;
    this.child = child;
    this.connection = connection;
    this.cwd = cwd;
  }

  static async connect(config: AcpClientConfig): Promise<AcpAgentHandle> {
    const child = spawn(config.command, [...config.args], {
      cwd: config.cwd,
      env: config.env ?? process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    const spawnFailure = new Promise<never>((_resolve, reject) => {
      child.once("error", (error) => {
        reject(new TransportError(`cannot start ${config.id} agent: ${error.message}`, { cause: error }));
      });
    });

    const stream = ndJsonStream(
      Writable.toWeb(child.stdin) as WritableStream<Uint8Array>,
      Readable.toWeb(child.stdout) as ReadableStream<Uint8Array>,
    );

    const app = registerClientHandlers(
      client({ name: `crossfire-${config.id}` }),
      config.policy,
      config.hooks ?? {},
    );
    const connection = app.connect(stream);
    const handle = new AcpAgentHandle(config.id, child, connection, config.cwd);

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      handle.stderrTail = `${handle.stderrTail}${chunk}`.slice(-STDERR_TAIL_BYTES);
    });

    const capabilities: ClientCapabilities = {
      fs: { readTextFile: true, writeTextFile: true },
      terminal: false,
      ...(config.capabilityMeta === undefined ? {} : { _meta: config.capabilityMeta }),
    };

    try {
      await Promise.race([
        connection.agent.request(methods.agent.initialize, {
          protocolVersion: PROTOCOL_VERSION,
          clientCapabilities: capabilities,
        }),
        spawnFailure,
      ]);
    } catch (error) {
      await handle.close();
      throw error instanceof TransportError
        ? error
        : new TransportError(
            `${config.id} agent failed to initialize: ${(error as Error).message}${handle.stderrSuffix()}`,
            { cause: error },
          );
    }

    return handle;
  }

  async newSession(options: NewSessionOptions = {}): Promise<string> {
    this.assertOpen();
    this.session?.dispose();
    try {
      this.session = await this.connection.agent.buildSession(options.cwd ?? this.cwd).start();
    } catch (error) {
      throw new TransportError(
        `${this.id} agent refused a new session: ${(error as Error).message}${this.stderrSuffix()}`,
        { cause: error },
      );
    }
    return this.session.sessionId;
  }

  /**
   * Drives one turn. The prompt request, the update queue, and the connection
   * are raced: an agent that dies or rejects mid-turn ends the stream with an
   * error event instead of leaving the broker waiting on an update that will
   * never arrive.
   */
  async *prompt(text: string): AsyncIterable<AgentEvent> {
    this.assertOpen();
    const session = this.session;
    if (session === undefined) {
      throw new TransportError(`${this.id} agent has no open session, call newSession first`);
    }

    // A rejected prompt request also rejects the update queue, so every racer
    // converts failure into an outcome rather than rejecting. Letting one of
    // them reject would turn a refused turn into an unhandled rejection.
    const failure = (error: unknown) => ({ kind: "failure" as const, error: asError(error) });

    const failed = new Promise<Error>((resolve) => {
      session.prompt(text).catch((error: unknown) => resolve(asError(error)));
    });
    const disconnected = this.connection.closed.then(
      () => new Error(`${this.id} agent connection closed mid turn${this.stderrSuffix()}`),
      (error: unknown) => asError(error),
    );

    let pending = session.nextUpdate();
    for (;;) {
      const outcome = await Promise.race([
        pending.then((message) => ({ kind: "update" as const, message }), failure),
        failed.then((error) => failure(error)),
        disconnected.then((error) => failure(error)),
      ]);

      if (outcome.kind === "failure") {
        yield { type: "error", message: outcome.error.message };
        return;
      }
      if (outcome.message.kind === "stop") {
        yield { type: "done", stop_reason: outcome.message.stopReason };
        return;
      }

      const event = normalizeSessionUpdate(outcome.message.update);
      if (event !== undefined) {
        yield event;
      }
      pending = session.nextUpdate();
    }
  }

  async cancel(): Promise<void> {
    if (this.closed || this.session === undefined) {
      return;
    }
    await this.connection.agent.notify(methods.agent.session.cancel, {
      sessionId: this.session.sessionId,
    });
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.session?.dispose();
    this.session = undefined;
    this.connection.close();
    this.child.kill();
    await new Promise<void>((resolve) => {
      if (this.child.exitCode !== null || this.child.signalCode !== null) {
        resolve();
        return;
      }
      this.child.once("close", () => resolve());
    });
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new TransportError(`${this.id} agent handle is closed`);
    }
  }

  private stderrSuffix(): string {
    const tail = this.stderrTail.trim();
    return tail.length === 0 ? "" : `\nagent stderr: ${tail}`;
  }
}
