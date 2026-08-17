"use strict";

const { decodeFrame } = require("../src/decode-frame.js");

module.exports.fuzz = function (data) {
  decodeFrame(data);
};
