"use strict";

/* The target's own test suite. It exercises well formed frames only, so it
   passes against both the vulnerable and the patched decoder. That is the
   point: it is the regression baseline a fix must not break, not a bug finder. */

const { strict: assert } = require("node:assert");
const { test } = require("node:test");

const { CHECKSUM_BYTES, HEADER_BYTES, MAGIC, decodeFrame } = require("../src/decode-frame.js");

function frameOf(payload) {
  const header = Buffer.alloc(HEADER_BYTES);
  MAGIC.copy(header);
  header[MAGIC.length] = payload.length;
  return Buffer.concat([header, payload]);
}

test("decodes a frame down to its payload and checksum", () => {
  const decoded = decodeFrame(frameOf(Buffer.from([0x70, 0x69, 0x00, 0x2a])));

  assert.deepEqual(decoded.payload, Buffer.from([0x70, 0x69]));
  assert.equal(decoded.checksum, 0x002a);
});

test("a frame carrying nothing but its checksum has an empty payload", () => {
  const decoded = decodeFrame(frameOf(Buffer.alloc(CHECKSUM_BYTES)));

  assert.equal(decoded.payload.length, 0);
  assert.equal(decoded.checksum, 0);
});

test("anything that is not a frame decodes to null", () => {
  assert.equal(decodeFrame(Buffer.from("hi")), null);
  assert.equal(decodeFrame(Buffer.from("NOPE\x00")), null);
});
