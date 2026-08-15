import { formatIssues } from "../contracts/issues.js";
import { LedgerEntrySchema } from "../contracts/ledger.js";
import { GENESIS_HASH, computeEntryHash } from "./hash.js";
import { readLedgerLines } from "./writer.js";

export type LedgerVerification =
  | { ok: true; entries: number }
  | { ok: false; failedAtIndex: number; round?: number; reason: string };

export function verifyLedger(path: string): LedgerVerification {
  const lines = readLedgerLines(path);
  let expectedPrevHash = GENESIS_HASH;
  let expectedRound = 1;

  for (const [index, line] of lines.entries()) {
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch (error) {
      return {
        ok: false,
        failedAtIndex: index,
        reason: `line is not valid JSON: ${(error as Error).message}`,
      };
    }

    const result = LedgerEntrySchema.safeParse(value);
    if (!result.success) {
      return {
        ok: false,
        failedAtIndex: index,
        reason: `entry does not match the ledger schema:\n${formatIssues(result.error.issues)}`,
      };
    }

    const entry = result.data;
    if (entry.prev_hash !== expectedPrevHash) {
      return {
        ok: false,
        failedAtIndex: index,
        round: entry.round,
        reason: `prev_hash ${entry.prev_hash} does not match the previous entry hash ${expectedPrevHash}`,
      };
    }

    const { entry_hash, ...linked } = entry;
    const recomputed = computeEntryHash(linked);
    if (recomputed !== entry_hash) {
      return {
        ok: false,
        failedAtIndex: index,
        round: entry.round,
        reason: `entry_hash ${entry_hash} does not match the hash of its content ${recomputed}`,
      };
    }

    if (entry.round !== expectedRound) {
      return {
        ok: false,
        failedAtIndex: index,
        round: entry.round,
        reason: `round ${entry.round} does not follow round ${expectedRound - 1}`,
      };
    }

    expectedPrevHash = entry_hash;
    expectedRound = entry.round + 1;
  }

  return { ok: true, entries: lines.length };
}
