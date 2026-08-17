"use strict";

/* The same decoder with the bounds check the fix adds, which is what "a fixed
   harness yields nothing within budget" is measured against. */

const { decodeFrame } = require("../src/decode-frame.js");

module.exports.fuzz = function (data) {
  decodeFrame(data, { boundsChecked: true });
};
