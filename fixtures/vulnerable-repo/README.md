# vulnerable-repo

The deliberately insecure target crossfire's detectors run against. Every bug in
here is seeded on purpose and every one of them is known to the test suite.

## What is seeded

| Detector | Finding | Where |
| --- | --- | --- |
| Semgrep (SAST) | `crossfire-insecure-strcpy`, an unbounded `strcpy` into `struct request.path` | `src/parse_request.c` |
| OSV-Scanner (SCA) | `minimist@1.2.0`, a pinned dependency with published advisories | `package-lock.json` |
| libFuzzer (fuzz) | heap-buffer-overflow reachable from the request line parser | `fuzz/parse_request_harness.c` |

The SAST finding and the crash are the same underlying bug seen two ways: the
scanner sees the dangerous call, the fuzzer proves it is reachable with a
concrete input. One fix closes both.

## Building the harness

```sh
./build.sh          # build/parse-request-fuzzer, the vulnerable parser
./build.sh fixed    # build/parse-request-fuzzer-fixed, the patched parser
```

`build.sh` needs a clang carrying the libFuzzer runtime. Apple's clang does not
ship one, so on macOS install `brew install llvm`; the script probes candidates
and fails loudly when none works.

The patched build is the same source compiled with `-DPARSE_REQUEST_FIXED`,
which bounds both copies. It is what "a fixed harness yields none within budget"
means in the detection tests.

## Running the target's tests

```sh
./test.sh
```

Well formed request lines only, so it passes against both builds. It is the
regression baseline for the test gate, not a bug finder.
