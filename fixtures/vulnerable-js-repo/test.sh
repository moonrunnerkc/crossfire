#!/bin/sh
# The target's test command, wired into crossfire.js-sample.json as testCommand.
set -eu

root=$(cd "$(dirname "$0")" && pwd)
cd "$root"
node --test "test/*.test.js"
