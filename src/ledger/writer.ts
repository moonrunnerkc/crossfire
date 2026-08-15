import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { formatIssues } from "../contracts/issues.js";
import type { LedgerEntry, LedgerEntryBody } from "../contracts/ledger.js";
import { LedgerEntryBodySchema, LedgerEntrySchema } from "../contracts/ledger.js";
import { GENESIS_HASH, computeEntryHash } from "./hash.js";

export class LedgerError extends Error {
  constructor(message: string, options?: { cause: unknown }) {
    super(message, options);
    this.name = "LedgerError";
  }
}

function readLines(path: string): string[] {
  let contents: string;
  try {
    contents = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw new LedgerError(`cannot read ledger ${path}: ${(error as Error).message}`, {
      cause: error,
    });
  }
  return contents.split("\n").filter((line) => line.trim().length > 0);
}

export function readLedgerLines(path: string): string[] {
  return readLines(path);
}

export function readLedger(path: string): LedgerEntry[] {
  return readLines(path).map((line, index) => {
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch (error) {
      throw new LedgerError(`ledger ${path} line ${index + 1} is not valid JSON`, { cause: error });
    }
    const result = LedgerEntrySchema.safeParse(value);
    if (!result.success) {
      throw new LedgerError(
        `ledger ${path} line ${index + 1} does not match the entry schema:\n${formatIssues(result.error.issues)}`,
        { cause: result.error },
      );
    }
    return result.data;
  });
}

export class LedgerWriter {
  private readonly path: string;

  constructor(path: string) {
    this.path = resolve(path);
    mkdirSync(dirname(this.path), { recursive: true });
  }

  lastEntry(): LedgerEntry | undefined {
    return readLedger(this.path).at(-1);
  }

  append(body: LedgerEntryBody): LedgerEntry {
    const result = LedgerEntryBodySchema.safeParse(body);
    if (!result.success) {
      throw new LedgerError(`invalid ledger entry:\n${formatIssues(result.error.issues)}`, {
        cause: result.error,
      });
    }

    const previous = this.lastEntry();
    const expectedRound = previous === undefined ? 1 : previous.round + 1;
    if (result.data.round !== expectedRound) {
      throw new LedgerError(
        `ledger expects round ${expectedRound} next, got round ${result.data.round}`,
      );
    }

    const linked = { ...result.data, prev_hash: previous?.entry_hash ?? GENESIS_HASH };
    const entry: LedgerEntry = { ...linked, entry_hash: computeEntryHash(linked) };
    appendFileSync(this.path, `${JSON.stringify(entry)}\n`, "utf8");
    return entry;
  }
}
