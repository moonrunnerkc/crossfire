import { closeSync, mkdirSync, openSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";

export interface JsonlWriter {
  readonly path: string;
  /** Appends one record, stamped with the time it was written. */
  write(record: Record<string, unknown>): void;
  close(): void;
}

/**
 * An append-only JSONL file held open for the life of a run. Writes are
 * synchronous and ordered: a log whose lines can interleave or arrive after the
 * process died is not evidence of anything.
 */
export function openJsonl(path: string): JsonlWriter {
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true });
  let fd: number | undefined = openSync(absolute, "a");

  return {
    path: absolute,

    write(record: Record<string, unknown>): void {
      if (fd === undefined) {
        throw new Error(`cannot write to ${absolute}, the log is closed`);
      }
      writeSync(fd, `${JSON.stringify({ ts: new Date().toISOString(), ...record })}\n`);
    },

    close(): void {
      if (fd !== undefined) {
        closeSync(fd);
        fd = undefined;
      }
    },
  };
}
