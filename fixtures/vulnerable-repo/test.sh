#!/bin/sh
# The target's test command, wired into crossfire.sample.json as target.testCommand.
set -eu

root=$(cd "$(dirname "$0")" && pwd)
cc_bin="${CC:-cc}"

mkdir -p "$root/build"
"$cc_bin" -g -O1 -I "$root/src" -o "$root/build/parse-request-tests" \
  "$root/src/parse_request.c" "$root/test/test_parse_request.c"

"$root/build/parse-request-tests"
