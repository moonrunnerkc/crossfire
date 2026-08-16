# Troubleshooting

crossfire fails closed, so most problems arrive as a specific message rather than as odd behavior. The strings below are the ones the code prints; find yours and work back from it.

## The run won't start

```text
crossfire: config file not found: /path/to/crossfire.json
```

The path is resolved against your current directory, not against the checkout. Pass an absolute path if you're unsure. A file that exists but isn't JSON gives you `invalid JSON in <path>:` with the parser's own complaint.

```text
crossfire: invalid config /path/to/crossfire.json:
  target.extra: unrecognized key
  detectors.fuzz.harnesses: fuzzing is enabled but no harnesses are configured
```

Every object in the schema is strict, so a typo'd or leftover key is an error rather than something ignored. All three detector blocks have to be present even when they're disabled, and `fuzz` can't be enabled with an empty `harnesses` array. Either add a harness or set `"enabled": false`.

```text
crossfire: the target /path/to/target is not a git repository, so a round cannot leave its commit
```

Checked before the first round, because a round that can't commit isn't a round. Run `git init` in the target, or point `repoPath` at the repository root.

**Rounds committed to the wrong repository.** There's no error for this one, which is what makes it worth knowing about. If `repoPath` points at a subdirectory of a larger repo, `git rev-parse` succeeds against the parent, and every round's `git add -A` commits that whole tree. Copy the target somewhere it can be its own repository first.

**`crossfire` on your PATH exits 0 and does nothing.** No output, no run directory, no error. `npm link` and a global install both produce a symlink, and `dist/cli.js` only runs itself when `import.meta.url` equals `pathToFileURL(process.argv[1])`. Node resolves the first through the symlink and leaves the second as the shim's own path, so the guard is false and the module loads without doing anything. Run `node dist/cli.js` instead.

```text
crossfire: the target does not build, so the run cannot start: the build command failed: <last lines of your build output>
```

The first build runs before detection, so nothing measures a binary nobody produced. Run your `buildCommand` by hand from the target root and fix it there. A build that overruns its 600s ceiling reports `the build command timed out after 600000ms` instead.

## The agents

```text
crossfire: cannot start grok agent: spawn grok ENOENT
```

The CLI isn't on the PATH of the process running crossfire. Check with `which grok` in the same shell. The Claude side has its own version of this: `cannot resolve @agentclientprotocol/claude-agent-acp/dist/index.js, is @agentclientprotocol/claude-agent-acp installed?` means you're running `dist/` without the `node_modules` it was built next to.

```text
crossfire: claude agent failed to initialize: <reason>
agent stderr: <the last 4KB the agent wrote>
```

The process started and then refused the ACP handshake. Not being logged in looks like this. The stderr tail is attached precisely so this doesn't come back as a bare "closed", so read it before anything else.

```text
crossfire: the crash-analysis turn timed out after 300000ms
```

The turn overran `loop.turnTimeoutMs`. The broker cancels the agent so it stops burning tokens on an answer nobody will read, and the run throws rather than continuing, because a timed-out turn isn't a finished round. Raise the budget for slow targets, or narrow `inScopeDirs` so a turn has less to read.

```text
crossfire: the fix turn answered with output the schema rejected:
  fixes.0.files_changed: a fix that changed no files is not a fix
```

Malformed agent output is rejected, never coerced. The related messages are `the <subtask> turn answered with no readable JSON object:` followed by a snippet of what came back, `the <agent> <subtask> turn produced no text`, and `the <agent> <subtask> turn ended as <stop_reason>, so its answer is incomplete`. All of them are the same underlying thing: the turn didn't produce a usable answer. The agent's full side of the conversation is in `runs/<timestamp>/transcripts/<agent>.jsonl`.

```text
crossfire: the fix report is for round 1, but round 2 is in progress
```

A report signed for the wrong round, signed by the wrong agent (`the fix report came back signed by grok`), or claiming a finding that wasn't in the batch (`the fix report claims sast-1a2b3c, which is not in round 2's batch`). These throw rather than terminating the run, because they mean the loop's state and the agent's are out of step.

## Detectors found nothing

Detector problems don't stop a run. They land in `run.jsonl` and in the ledger as a `DetectorRun` with a `status` and a `note`, so start there:

| Note | What happened |
| --- | --- |
| `disabled in the run config` | `enabled: false` for that detector. |
| `no fuzz engine adapter for afl++` | The engine is valid in the schema but only `libfuzzer` is implemented. |
| `harness binary build/parse-request-fuzzer is not built` | `entryPoint` doesn't exist. Set `buildCommand` so it's built before detection. |
| `budget of 1000ms was too short to start the harness` | `detectors.fuzz.timeBudgetMs`, divided by the number of harnesses, left no room to run. |
| `semgrep exit 7 produced no JSON: <stderr>` | Usually a bad `ruleset`, since the path is resolved inside the target. |
| `semgrep exceeded its 120000ms budget` | Raise `timeBudgetMs` or narrow `inScopeDirs`. |
| `every in-scope directory is excluded` | The exclusion set swallowed the scope. Check `excludedPaths` against the secret defaults. |
| `every configured lockfile is outside the scope or excluded` | Lockfile paths are relative to the target root, not to your shell. |
| `libFuzzer exited 1 without a crash artifact: <stderr>` | The harness aborted for a reason libFuzzer didn't record, often a missing runtime dependency. |

Findings below `loop.severityBar` are dropped at detection, before any agent sees them. A run that detects plenty and confirms nothing is usually a bar set too high, and `severityBar` applies to what the detector reported, not to what a model later called it.

## Fixes that don't stick

```text
  verify 1 survived
```

The repro still exits 0, so the bug is still there. That's the whole judgement: the finding stays open and goes into the next round. Check the fix report in `run.jsonl` against the diff in the target's round commit.

```text
  verify 1 inconclusive
```

The repro couldn't be run to completion, which is never treated as a pass. The `note` on the verify result says which:

- `the repro timed out after 120000ms`, so the repro is doing more than driving one input through one entry point.
- `the crash artifact .crossfire/crashes/parse-request/fuzz-1a2b3c4d5e6f.min is missing, so the repro proves nothing`. Something removed the artifact between detection and verification, usually a build script that cleans the tree.
- `the repro could not be run: <spawn error>`, so the command references a binary that isn't there.
- `the target did not build, so its repro could not be run`. The round's fix broke the build, and the findings stay open rather than being closed by a compiler error.

```text
  tests fail (regression)
crossfire: test-regression after 2 round(s)
```

The suite passed at the baseline captured before round one and fails now, so the run halts instead of stacking more fixes on a target the last round broke. The round is still committed and still in the ledger. A target whose suite was already failing at baseline doesn't trigger this; it just carries a failing test result through every round.

## Ledger and export

```text
crossfire: /path/to/runs/2026-08-15T10-00-00-000Z holds no ledger to continue
```

`resume` needs an existing `ledger.jsonl` in `--run-dir`, and it won't quietly start a fresh run instead. Check the path, or use `run` if you meant to start over.

An export whose chain doesn't verify prints the failure and no entries, and exits 1:

```json
{
  "verification": {
    "ok": false,
    "failedAtIndex": 0,
    "round": 1,
    "reason": "entry_hash 5f2c... does not match the hash of its content 9ab1..."
  },
  "entries": []
}
```

`entry_hash ... does not match the hash of its content` means an entry was edited after it was written. `prev_hash ... does not match the previous entry hash` means an entry was inserted, removed, or reordered. `round N does not follow round M` means the sequence has a gap, which is why every round commits and appends even when it changed nothing.

## Scoping refusals

Denials are recorded in the agent's transcript as `{"kind":"denied",...}` lines alongside the JSON-RPC traffic:

```json
{"kind":"denied","method":"fs/write_text_file","path":"/target/src/parse_request.c","reason":"grok has no write access"}
{"kind":"denied","method":"fs/read_text_file","path":"/target/.env","reason":".env is an excluded path"}
```

Both are working as intended. Grok is read plus execute by design, and the secret globs are merged into every run's exclusion set whatever the config says. If Claude is the one being refused a write, the path either resolves outside the target repo or matches an exclusion pattern. The agent sees JSON-RPC error code `-32001`, not an empty result, so a denial can't be mistaken for a file that was empty or a write that worked.
