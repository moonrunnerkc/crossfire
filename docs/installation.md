# Installation

crossfire is a CLI you build from source. There's no published package and no container image, because the thing it drives (two agent CLIs and a native toolchain on your machine) doesn't containerize into anything you'd want to maintain.

## What you need

| Tool | Version | Needed for | Check |
| --- | --- | --- | --- |
| Node | 20 or newer | everything | `node --version` |
| git | any recent | the target's per-round commits | `git --version` |
| semgrep | any | the SAST detector | `semgrep --version` |
| osv-scanner | any | the SCA detector | `osv-scanner --version` |
| clang with libFuzzer | any | building fuzz harnesses for C and C++ targets | the probe below |
| claude | any | fix turns | `claude --version` |
| grok | 1.0.4 or newer | analysis and confirmation turns | `grok --version` |

Node and git alone are enough for `--dry-run`. The rest only matter when you point crossfire at a real target.

`package.json` declares `"engines": { "node": ">=20" }`. Node 24 is what this repo is developed against.

## Build from source

```sh
git clone https://github.com/moonrunnerkc/crossfire.git
cd crossfire
npm install
npm run build
```

`npm run build` compiles `src/` into `dist/` with `tsconfig.build.json`, which narrows the root to `src/` so the entry point lands at `dist/cli.js` rather than `dist/src/cli.js`.

Run it as `node dist/cli.js` from the checkout.

`package.json` declares `"bin": { "crossfire": "./dist/cli.js" }`, but that name doesn't work yet: a linked or installed `crossfire` exits 0 and does nothing, because the entry point compares `import.meta.url` against `process.argv[1]` and npm's shim is a symlink, so the two never match. Use `node dist/cli.js`, or a shell alias for it, until that guard resolves the real path.

## The detector toolchain

crossfire shells out to these by name and records what happened rather than throwing, so a missing binary shows up as a detector run with `status: "error"` in the ledger instead of a crash. Install them however your platform prefers; the projects' own docs are the source of truth:

- Semgrep: [semgrep.dev/docs/getting-started](https://semgrep.dev/docs/getting-started)
- OSV-Scanner: [github.com/google/osv-scanner](https://github.com/google/osv-scanner)

For fuzzing, the harness is built by the target's own build command, not by crossfire, so what you need is a compiler that target can use. Ask a clang whether it can link a fuzz target rather than trusting its name, because `--version` tells you nothing about the runtime:

```sh
printf '#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { (void)d; (void)s; return 0; }\n' \
  | clang -fsanitize=fuzzer,address -x c - -o /tmp/fuzz-probe
```

Exit 0 means that clang works. On macOS, Apple's clang fails this with `library 'libclang_rt.fuzzer_osx.a' not found`; install LLVM (`brew install llvm`) and point `CC` at `/opt/homebrew/opt/llvm/bin/clang`. `fixtures/vulnerable-repo/build.sh` runs the same probe across a list of candidates, and fails with

```text
build.sh: no clang with the libFuzzer runtime found.
  macOS: brew install llvm   Linux: install clang with compiler-rt
  or set CC to a clang that accepts -fsanitize=fuzzer
```

On Linux, a clang packaged with compiler-rt is enough.

Only libFuzzer has an engine adapter today. The config schema accepts `afl++`, `jazzer`, and `atheris`, and a harness configured with any of them produces a detector run noting `no fuzz engine adapter for afl++`.

## The agents

Both agents are spawned as ACP subprocesses over stdio, in the target's working directory, and they have to already be logged in on the machine.

- Claude runs through `@agentclientprotocol/claude-agent-acp`, which is a dependency of this repo. crossfire resolves the adapter's entry point and runs it with the same Node binary running the broker, so which Claude answers doesn't depend on your shell's PATH.
- Grok is spawned as `grok agent stdio`, its native ACP surface. This was confirmed against Grok Build 1.0.4. There's no headless fallback.

## Verify the install

Types, lint, and the suite:

```sh
npm run check
```

```text
 Test Files  15 passed | 2 skipped (17)
      Tests  285 passed | 3 skipped (288)
```

The two skipped files are `test/smoke.test.ts` and `test/integration.test.ts`, which are guarded behind environment variables because they spawn the real agents and spend real tokens.

Then prove the shipped binary drives a whole round. This needs no scanners, no compiler, and no models:

```sh
mkdir -p /tmp/crossfire-demo/target/src
cd /tmp/crossfire-demo/target
printf '// the target under repair\n' > src/app.js
printf '#!/bin/sh\nexit 0\n' > run-tests.sh && chmod 755 run-tests.sh
git init -q -b main && git add -A && git commit -qm "the target as it arrived"

cat > /tmp/crossfire-demo/crossfire.json <<'JSON'
{
  "task": "Prove the install drives a round",
  "target": {
    "repoPath": "./target",
    "inScopeDirs": ["src"],
    "testCommand": "./run-tests.sh"
  },
  "loop": { "iterationCap": 2, "severityBar": "medium", "turnTimeoutMs": 10000 },
  "detectors": {
    "semgrep": { "enabled": false, "ruleset": "p/security-audit", "timeBudgetMs": 1000 },
    "osvScanner": { "enabled": false, "lockfiles": ["package-lock.json"], "timeBudgetMs": 1000 },
    "fuzz": { "enabled": false, "timeBudgetMs": 1000, "harnesses": [] }
  }
}
JSON
```

Back in the crossfire checkout:

```sh
node dist/cli.js run --config /tmp/crossfire-demo/crossfire.json --dry-run --run-dir /tmp/crossfire-demo/run
```

```text
round 1
  detected 1 finding(s) from semgrep:ok
  candidate-confirmation -> grok in 0s
  candidate dry-run-finding confirmed
  fix -> claude in 0s
  1 fix(es) reported
  verify 1 closed
  tests pass
  re-fuzz found 0 new
  committed 77dab6b67f
crossfire: clean after 1 round(s)
```

The sha differs on your machine; everything else shouldn't. `/tmp/crossfire-demo/run` now holds `ledger.jsonl` and `run.jsonl`, and the target has one new commit.

## What usually goes wrong

**The target isn't its own git repository.** crossfire checks before the first round and refuses: `the target <path> is not a git repository, so a round cannot leave its commit`. The subtler version of this passes the check and does damage: a `repoPath` pointing at a subdirectory of some larger repo resolves to that repo's git dir, and every round runs `git add -A` and commits the whole tree. This is why `crossfire.sample.json` points at `./fixtures/vulnerable-repo`, which lives inside this repo, and why the integration test copies the fixture to a temp directory and runs `git init` there first. Copy your target, or make sure `repoPath` is a repository root.

**The target doesn't build.** The first build runs before detection, and a failure stops the run before anything measures a binary nobody produced: `the target does not build, so the run cannot start: <the last lines of your build output>`. Targets that produce artifacts need `target.buildCommand` set. Without it, a round rebuilds nothing and grades the previous binary, so a real fix reads as a failure and a fix that doesn't compile reads as a pass.

**The Claude adapter can't be resolved.** `cannot resolve @agentclientprotocol/claude-agent-acp/dist/index.js, is @agentclientprotocol/claude-agent-acp installed?` means the dependency isn't there, usually because `dist/` was copied somewhere without `node_modules`. Run crossfire from a checkout that has had `npm install` run in it.
