"use strict";

/* Pass boundsChecked to run the patched decoder, the way the C fixture is built
   with -DPARSE_REQUEST_FIXED. The fixture ships both behaviours from one source
   so the detection gates can show a crash and its absence. */

const MAGIC = Buffer.from("SWRM", "ascii");
const CHECKSUM_BYTES = 2;
const HEADER_BYTES = MAGIC.length + 1;

/**
 * Decodes a framed message: the 4 byte magic, a 1 byte payload length, then the
 * payload, whose last two bytes are its checksum. Returns null for anything
 * that is not a frame.
 */
function decodeFrame(frame, { boundsChecked = false } = {}) {
  if (frame.length < HEADER_BYTES) {
    return null;
  }
  /* Compared byte by byte rather than in a loop or with Buffer.equals: each
     compare is its own branch, and those branches are the coverage feedback the
     fuzzer follows to the magic. Fold them together and the seeded crash stops
     being reachable in a bounded budget. */
  if (frame[0] !== MAGIC[0]) {
    return null;
  }
  if (frame[1] !== MAGIC[1]) {
    return null;
  }
  if (frame[2] !== MAGIC[2]) {
    return null;
  }
  if (frame[3] !== MAGIC[3]) {
    return null;
  }

  const declared = frame[MAGIC.length];
  if (boundsChecked && (declared < CHECKSUM_BYTES || HEADER_BYTES + declared > frame.length)) {
    return null;
  }

  /* The seeded bug: the declared length is trusted, so a frame that promises
     more payload than it carries reads past the end of what it actually has. */
  const payload = frame.subarray(HEADER_BYTES, HEADER_BYTES + declared);
  return {
    payload: payload.subarray(0, declared - CHECKSUM_BYTES),
    checksum: payload.readUInt16BE(declared - CHECKSUM_BYTES),
  };
}

module.exports = { decodeFrame, CHECKSUM_BYTES, HEADER_BYTES, MAGIC };
