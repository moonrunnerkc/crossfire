import { createHash } from "node:crypto";

import type { LinkedLedgerEntry } from "../contracts/ledger.js";

export const GENESIS_HASH = "0".repeat(64);

export function canonicalize(value: unknown): string {
  if (value === undefined) {
    return "null";
  }
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  const fields = Object.entries(value as Record<string, unknown>)
    .filter(([, fieldValue]) => fieldValue !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, fieldValue]) => `${JSON.stringify(key)}:${canonicalize(fieldValue)}`);
  return `{${fields.join(",")}}`;
}

export function hashPayload(value: unknown): string {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

export function computeEntryHash(entry: LinkedLedgerEntry): string {
  return hashPayload(entry);
}
