# Usage

Everything crossfire does starts from a JSON run config and one of three commands. The broker decides the rest.

## Commands

```text
crossfire run --config <path> [--dry-run] [--run-dir <dir>]
crossfire resume --config <path> --run-dir <dir> [--dry-run]
crossfire export --ledger <path> [--out <path>]
```

Run these as `node dist/cli.js <command>` from the checkout. The `crossfire` bin declared in `package.json` is not usable yet; see [installation.md](installation.md).

| Flag | Applies to | Default | What it does |
| --- | --- | --- | --- |
| `--config <path>` | `run`, `resume` | required | The run config. Paths inside it resolve relative to this file. |
| `--run-dir <dir>` | `run`, `resume` | `runs/<ISO timestamp>` | Where the ledger, the run log, and the transcripts are written. Required in practice for `resume`, which needs an existing ledger. |
| `--dry-run` | `run`, `resume` | off | Stubs the detectors and the agents, and leaves the target's history alone. Nothing else is stubbed. |
| `--ledger <path>` | `export` | required | The `ledger.jsonl` to verify and print. |
| `--out <path>` | `export` | stdout | Write the export here instead of printing it. |

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | The run ended clean, or the exported chain verified. |
| 1 | The run hit the iteration cap, halted on a test regression, or was aborted. For `export`, the chain is broken. |
| 2 | Usage or configuration error: unknown command, missing flag, unreadable config, a run directory with no ledger to continue. |

`resume` reads the ledger's last entry and starts at the round after it. The iteration cap counts every round the ledger already holds, so resuming can't spend the budget twice. Findings aren't resumed: detection is deterministic, so a resumed round re-finds whatever is still there instead of trusting a stale list.

## The run config

`crossfire.sample.json` is a working config for the fixture in `fixtures/vulnerable-repo`. Every object in the schema is strict, so an unknown key is an error rather than something silently ignored, and the whole `detectors` block is required even when all three are disabled.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `task` | string | required | One line describing the run. It goes into every prompt. |
| `target.repoPath` | string | required | Resolved relative to the config file. Must be a git repository root. |
| `target.inScopeDirs` | string[] | required, min 1 | What detection scans and what the fix prompt asks Claude to stay inside. |
| `target.excludedPaths` | string[] | `[]` | Globs nobody may touch. The secret defaults below are always merged in. |
| `target.testCommand` | string | required | The target's own suite. Captured as a baseline, re-run as a gate. |
| `target.buildCommand` | string | absent | Run before the first round and after every fix. Required for any target with compiled artifacts. |
| `loop.iterationCap` | integer, 1 to 100 | `5` | Hard maximum number of rounds. |
| `loop.severityBar` | `info` \| `low` \| `medium` \| `high` \| `critical` | `medium` | Findings below it are dropped at detection. |
| `loop.turnTimeoutMs` | positive integer | `300000` | Deadline for a single agent turn. |
| `supplemental.coldHunt` | boolean | `false` | One Grok turn per round to raise what the detectors missed. |
| `supplemental.planner` | boolean | `false` | One Grok turn to summarize the batch into a paragraph of the fix prompt. |
| `detectors.semgrep.enabled` | boolean | `true` | |
| `detectors.semgrep.ruleset` | string | required | Passed to `semgrep scan --config`. A registry id or a path in the target. |
| `detectors.semgrep.timeBudgetMs` | positive integer | required | |
| `detectors.osvScanner.enabled` | boolean | `true` | |
| `detectors.osvScanner.lockfiles` | string[] | required, min 1 | Passed as `--lockfile=` arguments. |
| `detectors.osvScanner.timeBudgetMs` | positive integer | required | |
| `detectors.fuzz.enabled` | boolean | `true` | Enabled with no harnesses is a config error. |
| `detectors.fuzz.timeBudgetMs` | positive integer | required | Split evenly across the harnesses. |
| `detectors.fuzz.harnesses` | array | required | See below. |

Each harness:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | lowercase slug | Must match `^[a-z0-9][a-z0-9._-]*$` and be unique in the run. |
| `language` | `c` \| `cpp` \| `java` \| `javascript` \| `typescript` \| `python` | Checked against the engine. |
| `engine` | `libfuzzer` \| `afl++` \| `jazzer` \| `jazzer.js` \| `atheris` | `libfuzzer` and `afl++` take C and C++, `jazzer` takes Java, `jazzer.js` takes JavaScript and TypeScript, `atheris` takes Python. `libfuzzer` and `jazzer.js` are the two with adapters. |
| `entryPoint` | path | Relative to the target root: the built harness binary for `libfuzzer`, the CommonJS module exporting `fuzz` for `jazzer.js`. |
| `corpusDir` | path | Seed corpus. Copied to a temp directory before fuzzing, so the target's corpus never grows. |

These secret globs are always excluded, on top of whatever `excludedPaths` adds: `.env`, `.env*`, `**/.env*`, `**/.npmrc`, `**/.netrc`, `**/.git-credentials`, `**/.ssh/**`, `**/.aws/**`, `**/.gnupg/**`, `**/secrets/**`, `**/*credentials*`, `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.pfx`, `**/*.keystore`, `**/id_rsa*`, `**/id_ed25519*`. Symlinks are resolved before the check, so a link pointing at `/etc` or at `.env` is denied on where it lands rather than on how it's spelled.

## Budgets that aren't in the config

These are constants in the gates and the fuzz engine. They're deliberately not configurable, and changing one means changing the code:

| Budget | Value | Where |
| --- | --- | --- |
| Repro command timeout | 120s | `gates/verify.ts` |
| Test command timeout | 600s | `gates/test-gate.ts` |
| Build command timeout | 600s | `gates/build.ts` |
| Post-fix re-fuzz budget | 60s | `gates/refuzz.ts` |
| Fuzz seed | 1 | `detection/fuzz.ts`, fixed so a run is reproducible |
| Per-input timeout | 25s | `detection/libfuzzer-driver.ts`, the ceiling OSS-Fuzz uses, so a hang is a finding |
| Restarts per harness | 32 | `detection/libfuzzer-driver.ts`, a backstop against a harness that crashes instantly forever |

## The repro convention

A finding's repro is a shell command the broker runs from the target root.

```text
exit 0        the bug is still present
non-zero      the bug is gone
```

That's the only thing that decides whether a fix worked. A repro that can't be run to completion is inconclusive, never a pass: a blown timeout, a killed process, and a missing crash artifact all produce the same non-zero exit a real fix does, so treating them as success would close bugs on a technicality.

A fuzzer repro replays the minimized crash artifact through the harness and flips the exit code with `!`. A scanner repro starts as "the rule still fires here" and is replaced by the dynamic proof Grok builds when it confirms the candidate.

## Examples

### Drive the loop with nothing installed

The dry run stubs the detectors and the agents. The broker, the gates, and the ledger are real, which makes it the fastest way to check that a config, a target, and its test command hang together:

```sh
node dist/cli.js run --config crossfire.json --dry-run --run-dir runs/dry
```

Its one synthetic finding hangs on a marker file written inside the run directory. The repro exits 0 while the marker is absent and the stub fix creates it, so the repro flips exactly the way a real one does and the target is never touched. The round's ledger entry records the sha the run read rather than one it made, because a dry run has nothing of its own to commit.

### A real run against the bundled fixture

`fixtures/vulnerable-repo` seeds an unbounded `strcpy` that Semgrep matches, a `minimist@1.2.0` pin that OSV-Scanner reports advisories against, and a heap-buffer-overflow the libFuzzer harness reaches. The SAST finding and the crash are the same bug seen two ways, so one fix closes both.

The fixture lives inside this repository, so copy it somewhere it can be its own git repo before pointing a run at it. Otherwise the round's `git add -A` commits the crossfire checkout:

```sh
cp -R fixtures/vulnerable-repo /tmp/vulnerable-repo
cd /tmp/vulnerable-repo
rm -rf build .crossfire
./build.sh
git init -q -b main && git add -A && git commit -qm "the target as it arrived"
```

Point `target.repoPath` at `/tmp/vulnerable-repo` in a copy of `crossfire.sample.json`, then:

```sh
node dist/cli.js run --config /tmp/crossfire.json
```

Each round prints one line per phase, and the same events are written to `run.jsonl` as JSON, so what you watch and what you read afterwards can't drift.

### The JavaScript fixture

`fixtures/vulnerable-js-repo` is the same shape for the Jazzer.js engine: a frame
decoder that trusts a length field, reached by `fuzz/decode-frame.fuzz.js`, and
the same decoder behind the bounds check in `fuzz/decode-frame-fixed.fuzz.js`.
`crossfire.js-sample.json` points at it. `build.sh` is `npm install`, because
what makes a JavaScript harness runnable is the target's own Jazzer.js.

### Fuzzing crossfire itself

`crossfire.self.json` runs the two harnesses in `fuzz/` against this repository:
the boundary where a model's answer meets the ledger, and the parsers that
normalize a fuzz engine's crash output. They load `dist/`, so `npm run build`
comes first, which is what the config's `buildCommand` does. To run one on its
own without the loop:

```sh
npm run build
node_modules/.bin/jazzer fuzz/crash-report.fuzz.cjs fuzz/corpus/crash-report -- -max_total_time=60
```

### Turn on the supplemental passes

Both are off unless a config asks for them, and neither can change what the loop does:

```json
{
  "supplemental": { "coldHunt": true, "planner": true }
}
```

`coldHunt` gives Grok one turn per round to raise defects the detectors missed, capped at 10 raises. A raise is a candidate: the broker assigns its id, puts it through the finding schema, and sends it through the same confirmation any scanner candidate gets, so it can't reach a fix round without a repro the broker ran. `planner` gives Grok one turn to summarize the confirmed batch into at most 1200 characters, which reach one section of the fix prompt and nothing else.

### Read a finished run

```sh
node dist/cli.js export --ledger runs/2026-08-15T10-00-00-000Z/ledger.jsonl --out ledger-export.json
```

The export verifies the chain first. If verification fails, it exports the failure and no entries, so a tampered ledger can't travel as a clean one, and the exit code is 1.

## What a run leaves behind

```text
runs/<timestamp>/
  ledger.jsonl            one hash-chained entry per round
  run.jsonl               one line per phase: detector runs, turns, verdicts, gates
  transcripts/claude.jsonl
  transcripts/grok.jsonl  every JSON-RPC line both ways, plus every policy refusal
```

Plus exactly one commit per round in the target, empty rounds included.

A ledger entry carries the round number, its start and end timestamps, every detector run, a sha256 of the findings batch, a sha256 of the fix report, the verify result per finding, the test result, the round's git sha, the previous entry's hash, and its own. `run.jsonl` events are typed: `run-started`, `round-started`, `detected`, `raised`, `candidate-verdict`, `analyzed`, `turn`, `planned`, `fixed`, `built`, `verified`, `tested`, `refuzzed`, `round-committed`, `terminated`.

## Why a run stops

Four reasons, all mechanical: nothing survived a full detect and verify pass, the iteration cap, a test regression against the baseline captured before round one, or a manual abort. Malformed agent output, an overrun turn, and a fix report signed for the wrong round aren't termination reasons. They throw, because a run that crashed isn't a run that finished.
