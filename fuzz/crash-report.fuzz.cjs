"use strict";

/**
 * The parsers that normalize a fuzz engine's crash output into one report
 * shape. They read whatever the engine printed, which on a bad day is
 * truncated, interleaved with the target's own stderr, or shaped by the very
 * input that caused the crash. A crash, a hang, or a report that breaks the
 * shape a Finding needs is a finding.
 *
 * Run it through crossfire with crossfire.self.json, or on its own:
 *
 *   npm run build
 *   node_modules/.bin/jazzer fuzz/crash-report.fuzz.cjs fuzz/corpus/crash-report
 */

const { strict: assert } = require("node:assert");

const { parseCrashReport } = require("../dist/detection/crash-report.js");
const { parseJazzerReport } = require("../dist/detection/jazzer-js.js");

const PARSERS = [
  ["libfuzzer", parseCrashReport],
  ["jazzer.js", parseJazzerReport],
];

/** What toSlug promises, and what a Finding's class is read as. */
const SLUG = /^[a-z0-9][a-z0-9-]*$/;

module.exports.fuzz = function (data) {
  const output = data.toString("utf8");

  for (const [engine, parse] of PARSERS) {
    const report = parse(output);
    if (report === undefined) {
      continue;
    }

    assert.ok(SLUG.test(report.kind), `${engine}: crash kind ${JSON.stringify(report.kind)}`);
    assert.ok(
      report.signature.startsWith(report.kind),
      `${engine}: signature ${JSON.stringify(report.signature)} does not open with its kind`,
    );

    for (const frame of report.frames) {
      assert.ok(
        typeof frame.functionName === "string" && frame.functionName.length > 0,
        `${engine}: frame with no function name`,
      );
      if (frame.file !== undefined) {
        assert.ok(frame.file.length > 0, `${engine}: frame with an empty file`);
      }
      if (frame.line !== undefined) {
        // A Finding's line is a positive integer, so a frame that cannot supply
        // one has to report no line rather than a number the contract rejects.
        assert.ok(
          Number.isSafeInteger(frame.line) && frame.line > 0,
          `${engine}: frame line ${frame.line} is not a line number`,
        );
      }
    }
  }
};
