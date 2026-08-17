"use strict";

/**
 * The boundary where a model's answer meets the ledger. A turn comes back as
 * text, the broker parses it against a contract, and what reaches the ledger is
 * a hash of the parsed answer rather than the answer. This harness feeds
 * arbitrary bytes in as that text and holds the boundary to golden rule 5: the
 * broker writes the ledger, the model never does.
 *
 * Run it through crossfire with crossfire.self.json, or on its own:
 *
 *   npm run build
 *   node_modules/.bin/jazzer fuzz/ledger-boundary.fuzz.cjs fuzz/corpus/ledger-boundary
 */

const { strict: assert } = require("node:assert");
const { mkdtempSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const { BrokerError } = require("../dist/broker/errors.js");
const { parseAgentJson } = require("../dist/broker/parse.js");
const {
  CandidateVerdictSchema,
  ColdHuntRaisesSchema,
  CrashAnalysisSchema,
  FixPlanSchema,
  FixReportSchema,
} = require("../dist/contracts/index.js");
const {
  LedgerError,
  LedgerWriter,
  hashPayload,
  readLedgerLines,
  verifyLedger,
} = require("../dist/ledger/index.js");

/** Every subtask whose answer the broker parses out of a turn. */
const CONTRACTS = [
  ["fix", FixReportSchema],
  ["crash-analysis", CrashAnalysisSchema],
  ["candidate-confirmation", CandidateVerdictSchema],
  ["cold-hunt", ColdHuntRaisesSchema],
  ["fix-planning", FixPlanSchema],
];

const LEDGER_PATH = join(mkdtempSync(join(tmpdir(), "crossfire-fuzz-ledger-")), "ledger.jsonl");
const ledger = new LedgerWriter(LEDGER_PATH);

/** Everything in an entry except the hash of the answer is the broker's own. */
function brokerEntry(round, fixesHash) {
  return {
    round,
    started_at: "2026-01-01T00:00:00.000Z",
    ended_at: "2026-01-01T00:01:00.000Z",
    detector_runs: [],
    findings_hash: "a".repeat(64),
    fixes_hash: fixesHash,
    verify_results: [],
    test_result: { status: "pass", command: "npm test", exit_code: 0, duration_ms: 1 },
    git_sha: "b".repeat(40),
  };
}

function withoutChain(entry) {
  const body = { ...entry };
  delete body.prev_hash;
  delete body.entry_hash;
  return body;
}

function asJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    // Not JSON at all, which is most of what a fuzzer produces and most of what
    // a turn that answered in prose looks like.
    return undefined;
  }
}

module.exports.fuzz = function (data) {
  const answer = data.toString("utf8");
  writeFileSync(LEDGER_PATH, "");

  const parsed = [];
  for (const [subtask, schema] of CONTRACTS) {
    try {
      parsed.push(parseAgentJson(schema, answer, subtask));
    } catch (error) {
      // An answer the schema rejects has to halt the round, and BrokerError is
      // how the broker says so. Anything else escaping is the finding.
      if (!(error instanceof BrokerError)) {
        throw error;
      }
    }
  }
  assert.equal(readLedgerLines(LEDGER_PATH).length, 0, "reading a turn wrote to the ledger");

  // The model's own object, handed straight to the writer. A ledger entry is
  // the broker's to build, so this has to be refused whatever it says.
  const claimed = asJson(answer);
  if (claimed !== null && typeof claimed === "object") {
    try {
      ledger.append(claimed);
    } catch (error) {
      if (!(error instanceof LedgerError)) {
        throw error;
      }
    }
    assert.equal(readLedgerLines(LEDGER_PATH).length, 0, "model output became a ledger entry");
  }

  const opening = brokerEntry(1, hashPayload(null));
  const recording = brokerEntry(2, hashPayload(parsed));
  ledger.append(opening);
  ledger.append(recording);

  const written = readLedgerLines(LEDGER_PATH).map((line) => JSON.parse(line));
  assert.equal(written.length, 2, "the broker's two appends did not write two entries");
  // Every field but the hash of the answer is a constant chosen here, so a byte
  // of the answer that reached an entry shows up as a mismatch.
  assert.deepEqual(withoutChain(written[0]), opening);
  assert.deepEqual(withoutChain(written[1]), recording);
  assert.equal(verifyLedger(LEDGER_PATH).ok, true, "the chain stopped verifying");
};
