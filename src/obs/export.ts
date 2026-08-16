import { resolve } from "node:path";

import type { LedgerEntry } from "../contracts/index.js";
import type { LedgerVerification } from "../ledger/index.js";
import { readLedger, verifyLedger } from "../ledger/index.js";

export interface LedgerExport {
  ledger_path: string;
  exported_at: string;
  verification: LedgerVerification;
  /** Empty when the chain does not verify: a broken chain has nothing to export. */
  entries: LedgerEntry[];
}

/**
 * Verifies the chain first and exports the entries only if it holds. Handing
 * back entries from a chain that failed verification would let a tampered
 * ledger travel as a clean one, which is the single thing the ledger exists to
 * prevent.
 */
export function exportLedger(path: string): LedgerExport {
  const verification = verifyLedger(path);

  return {
    ledger_path: resolve(path),
    exported_at: new Date().toISOString(),
    verification,
    entries: verification.ok ? readLedger(path) : [],
  };
}
