# crossfire

A deterministic broker that drives two ACP coding agents through a
detect, analyze, fix, verify loop against a target repository.

Deterministic detectors find the bugs. A fuzzer produces crashes and static
scanners produce candidates. Grok reasons over what they found and proves a
candidate by building a repro. Claude patches. The broker verifies every fix by
re-running the repro itself and records the round as a hash-chained ledger entry
and a git commit.

The broker owns all control flow. Models answer questions inside a round; they
never decide routing, what happens next, or when to stop.

## Requirements

- Node 20 or newer.
- `git`, and a target that is its own git repository.
- For the detectors: [semgrep](https://semgrep.dev), [osv-scanner](https://github.com/google/osv-scanner),
  and a fuzz harness with an engine crossfire has an adapter for (libFuzzer today).
- For the agents: the `claude` and `grok` CLIs, logged in.

None of these are needed for `--dry-run`.

```sh
npm install
npm run check      # types, lint, and the full suite
npm run build      # dist/, including the crossfire CLI entry point
```

## Running

```sh
node dist/cli.js run --config crossfire.json
node dist/cli.js run --config crossfire.json --dry-run
node dist/cli.js resume --config crossfire.json --run-dir runs/2026-08-15T10-00-00-000Z
node dist/cli.js export --ledger runs/2026-08-15T10-00-00-000Z/ledger.jsonl
```

`npm run build` first. The package declares a `crossfire` bin, so `npm link` puts
the same entry point on your PATH as `crossfire run ...`.

`--dry-run` stubs the detectors and the agents and nothing else. The broker, the
gates, git, and the ledger still run for real, so it exercises the whole loop
without scanners, a compiler, or a model. It is the fastest way to check that a
config, a target, and its test command hang together.

Exit codes: `0` when the run ended clean, `1` when it hit the iteration cap,
halted on a test regression, or was aborted, and `2` for a usage or
configuration error.

## Configuration

`crossfire.sample.json` is a working config for the fixture in
`fixtures/vulnerable-repo`. The fields:

| Field | What it does |
| --- | --- |
| `task` | One line describing what the run is for. It goes into every prompt. |
| `target.repoPath` | The repository to work on, resolved relative to the config file. |
| `target.inScopeDirs` | Directories the run is about. Detection and the fix prompt use them. |
| `target.excludedPaths` | Globs no agent and no detector may touch. The secret defaults are always added. |
| `target.buildCommand` | Optional. Run before the first round and after every fix. |
| `target.testCommand` | The target's own suite. Captured as a baseline, re-run as a gate. |
| `loop.iterationCap` | The hard maximum number of rounds. |
| `loop.severityBar` | Findings below this are dropped at detection. |
| `loop.turnTimeoutMs` | How long a single agent turn may take. |
| `supplemental.coldHunt` | Off by default. See below. |
| `supplemental.planner` | Off by default. See below. |
| `detectors.semgrep` | Ruleset and time budget for SAST. |
| `detectors.osvScanner` | Lockfiles and time budget for SCA. |
| `detectors.fuzz` | Time budget and one entry per harness: id, language, engine, entry point, corpus. |

A target that builds artifacts needs `buildCommand`. A crash repro replays a
binary and the fuzzer fuzzes one, so without a rebuild between a fix and the
checks that judge it, the round measures the previous binary: a real fix reads as
a failure, and a fix that does not compile reads as a pass.

## The repro convention

A finding's repro is a shell command, run by the broker from the target's root.

```
exit 0        the bug is still present
non-zero      the bug is gone
```

This is the only thing that decides whether a fix worked. Everything that cannot
be run to completion is inconclusive rather than a pass, because a blown timeout,
a killed process, and a missing crash artifact all produce the same non-zero exit
a real fix does.

For a fuzzer finding, the repro replays the minimized crash artifact through the
harness and normalizes its exit code. For a scanner candidate, the repro is the
dynamic proof Grok built, and the broker runs it before the candidate is allowed
into a fix round.

## A round

1. **Detect.** Scanners and the fuzzer run against the scope. The fuzzer's
   crashes arrive confirmed; the scanners' findings arrive as candidates.
2. **Confirm.** Each candidate goes to Grok, which either dismisses it or returns
   a repro. The broker runs that repro. A candidate whose repro does not
   reproduce is dropped, whatever the verdict said.
3. **Analyze.** Each new crash goes to Grok for a root cause, a severity, and a
   repro. A proposed repro replaces the detector's only after the broker has run
   it and seen it reproduce.
4. **Fix.** The confirmed batch goes to Claude with every repro that has to be
   made to fail, the in scope directories, and the diff of what earlier rounds
   changed.
5. **Verify.** The target is rebuilt, every repro is re-run, and the target's own
   suite is compared against the baseline captured before round one. Then the
   fuzzer runs again for a bounded budget against the patched build, and anything
   it finds that is not already open enters the next round confirmed.

The round ends with exactly one git commit in the target and exactly one
hash-chained ledger entry, always, so a gap in either sequence cannot be
confused with a round somebody removed.

A run stops for four reasons and no others: nothing survived a full detect and
verify pass, the iteration cap, a test regression, or a manual abort. Malformed
agent output, a turn that overran its timeout, and a fix report signed for the
wrong round are not termination reasons. They throw, because a run that crashed
is not a run that finished.

## Supplemental passes

Both are off unless a config turns them on, and neither can change what the loop
does.

- `supplemental.coldHunt` gives Grok one turn per round to raise defects the
  detectors missed. A raise is a candidate: it goes through the same confirmation
  every scanner candidate gets, so it cannot reach a fix round without a repro
  the broker ran.
- `supplemental.planner` gives Grok one turn to summarize the confirmed batch
  into a paragraph of the fix prompt. It is bounded by schema, and nothing but
  the prompt builder ever reads it.

## What a run leaves behind

```
runs/<timestamp>/
  ledger.jsonl            one hash-chained entry per round
  run.jsonl               structured events: detectors, turns, verdicts, gates
  transcripts/claude.jsonl
  transcripts/grok.jsonl  raw JSON-RPC both ways, plus every refusal
```

Plus one commit per round in the target repository.

`crossfire export --ledger <path>` verifies the chain and prints it. A ledger
that fails verification exports its failure and no entries, so a tampered ledger
cannot travel as a clean one. Its exit code is non-zero when the chain is broken.

## Scoping

Grok has read and execute access and no write access at all. Claude is the only
agent that writes. Neither can read or write an excluded path, and the detectors
run under the same exclusion set. This is enforced in the ACP permission and
filesystem handlers rather than in prompt text, because an agent cannot be argued
out of a handler that refuses.

Known limit: Claude's write scope is the repository minus the exclusion set,
not `inScopeDirs`. The fix prompt asks it to stay inside them; that ask is not
yet enforcement.

## Tests

```sh
npm run check                                             # everything below except the guarded runs
CROSSFIRE_SMOKE=1 npx vitest run test/smoke.test.ts        # real Claude and Grok, one trivial prompt each
CROSSFIRE_INTEGRATION=1 npx vitest run test/integration.test.ts   # the whole loop against the fixture
```

The integration run needs every external tool and both agents, takes about seven
minutes, and spends real tokens. It drives the seeded crash and the seeded
scanner finding through the full loop against a temporary clone of
`fixtures/vulnerable-repo`.
