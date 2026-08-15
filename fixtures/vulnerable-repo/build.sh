#!/bin/sh
# Builds the libFuzzer harness for the parse_request target.
#
#   ./build.sh              -> build/parse-request-fuzzer        (vulnerable)
#   ./build.sh fixed        -> build/parse-request-fuzzer-fixed  (patched)
#
# Apple's clang ships without the libFuzzer runtime, so the candidates below are
# probed by actually compiling a one line harness rather than trusted by name.
set -eu

mode="${1:-vulnerable}"
root=$(cd "$(dirname "$0")" && pwd)

supports_fuzzer() {
  probe_dir=$(mktemp -d)
  printf '#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { (void)d; (void)s; return 0; }\n' \
    >"$probe_dir/probe.c"
  if "$1" -fsanitize=fuzzer,address -o "$probe_dir/probe" "$probe_dir/probe.c" >/dev/null 2>&1; then
    rm -rf "$probe_dir"
    return 0
  fi
  rm -rf "$probe_dir"
  return 1
}

find_clang() {
  for candidate in "${CC:-}" /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang clang; do
    [ -n "$candidate" ] || continue
    command -v "$candidate" >/dev/null 2>&1 || continue
    if supports_fuzzer "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

if ! clang_bin=$(find_clang); then
  echo "build.sh: no clang with the libFuzzer runtime found." >&2
  echo "  macOS: brew install llvm   Linux: install clang with compiler-rt" >&2
  echo "  or set CC to a clang that accepts -fsanitize=fuzzer" >&2
  exit 1
fi

case "$mode" in
  vulnerable) out="$root/build/parse-request-fuzzer"; defines="" ;;
  fixed) out="$root/build/parse-request-fuzzer-fixed"; defines="-DPARSE_REQUEST_FIXED" ;;
  *) echo "build.sh: unknown mode '$mode', expected vulnerable or fixed" >&2; exit 2 ;;
esac

mkdir -p "$root/build"
# shellcheck disable=SC2086
"$clang_bin" -g -O1 -fsanitize=fuzzer,address -I "$root/src" $defines \
  -o "$out" "$root/src/parse_request.c" "$root/fuzz/parse_request_harness.c"

echo "built $out with $clang_bin"
