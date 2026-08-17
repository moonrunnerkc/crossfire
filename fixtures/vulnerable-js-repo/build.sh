#!/bin/sh
# Installs the target's dependencies, which is what makes its harness runnable:
# crossfire spawns Jazzer.js from node_modules/.bin inside the target itself.
set -eu

root=$(cd "$(dirname "$0")" && pwd)
cd "$root"
npm install --no-audit --no-fund

echo "installed $root/node_modules"
