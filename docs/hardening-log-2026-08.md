# Hardening run log (H0 to H10)

Running record. Decisions taken without checking in, per the standing instruction.

## H0: mainline decided

`main` and the v13 lineage have **no common ancestor** (`git merge-base` exits 1). Two
disjoint histories in one repo: `main` is swarm-orchestrator@12.1.1, a PR auditor, last
commit 2026-07-26. The v13 lineage is 13.0.0, an evidence-first coding agent, 119 commits
in four days. `docs/build-guide.md` §5.1 says "v13 replaces v12 outright". The v13 lineage
had **no mainline branch**, so one was cut.

Decision: `v13-main` from `redteam/loop/lap-2-attack`. `origin/main` and `v12-final`
untouched; the §5.1 default-branch repoint is a separate release decision.

## H1: hardening merged

`v13-main` = `2cc52b86`, squash of the seven non-empty commits from `crossfire-fuzz-02`.
Tree byte-identical to `crossfire-fuzz-02` (`b7c7ca90`), so the squash was provably
lossless. Gates: typecheck 0, lint 0, **973 tests**, fuzz:build 0, all three harnesses ran
seeds. Pushed. `crossfire-fuzz-02` kept for ledger `git_sha` provenance.

Found: repo ruleset `restrictdelete` (id 15229475) restricts ref **creation**; the push
succeeded only via owner bypass. Feeds H9.

## H1a: Node version aligned

CI had **never been green** on the v13 lineage. `.nvmrc` said 22; the coverage cycle spawns
`--test-isolation=process`, which Node 22 rejects as a bad option (verified: 22.22.3 does
not list the flag, 24.15.0 does), so no lcov artifact is written and the arms correctly
report not measured. Five declarations aligned to 24 (`.nvmrc`, engines, CLAUDE.md,
AGENTS.md, docs/build-guide.md). `d2aa3722`. **CI green**, run 32072376130, Node v24.19.0.

Found and not fixed: `src/gates/corpus-replay.test.ts` resolves the v12 falsification
corpus via `git archive main`, which works locally (a local `main` exists) but not in CI
(only `origin/main` exists), so 1,043 corpus cases have **never been replayed in CI**. The
suite skips visibly by design. `git archive origin/main` works. Feeds H10.

## H2: answered, not passed

Transport defect found first: agents were connected eagerly at run start, so Claude idled
~30 min through detection and Grok's turns and was gone when first used. A probe held the
same adapter idle 2280s under no load and it survived, so idling alone is not the cause;
macOS retains no log for the window. Root cause **not established**. Fixed with the
cause-independent option: connect per turn, close after (`f4eb45b`, branch
`per-turn-agent-connection`). Rule 7 made literal. Re-run completed, so concurrent fuzz
load is implicated.

Convergence: **one round, not two**. Grok's repro generalised (`(a*)(a*)(a*)(a*)(a*)(a*)$`)
and named the general defect, Claude fixed it generally, so no residual existed. Graded
against the original human fix across 29 patterns in both directions: **zero behavioural
differences**.

Two gaps recorded:
- The loop terminates on `open.length === 0` where `open` is refreshed only by the **fuzz**
  cross-check. Semgrep and OSV are not re-run before "clean". Golden rule 3 requires a full
  detect-and-verify pass; the implementation does not meet it. Not patched here.
- The fix prompt does not ask for regression tests; two fixes have now shipped unpinned.
- Finding-id stability was never stressed: the patch landed in `regex-safety.ts` while the
  flagged construct sits in `search-tool.ts`, so no line shifted.

## H3: SAST packs probed, none worth adding

Seventeen packs run standalone against `src` with `*.test.ts` excluded, semgrep 1.136.0.
Rule counts confirm each pack loaded real rules and scanned 113 to 117 files at ~100%
parse, so these are genuine null results, not load failures.

| pack | rules | findings |
|---|---|---|
| **p/default** | **213** | **7** |
| p/gitleaks | 174 | 0 |
| p/owasp-top-ten | 80 | 0 |
| p/javascript | 74 | 0 |
| p/typescript | 74 | 0 |
| p/cwe-top-25 | 44 | 0 |
| p/secrets | 41 | 0 |
| p/nodejs | 36 | 0 |
| p/trailofbits | 26 | 0 |
| p/security-audit | 23 | 0 |
| p/r2c-security-audit | 23 | 0 |
| p/xss | 12 | 0 |
| p/insecure-transport | 8 | 0 |
| p/jwt | 6 | 0 |
| p/eslint-plugin-security | 6 | 0 |
| p/react | 4 | 0 |
| p/command-injection | 2 | 0 |
| p/github-actions (vs .github) | 11 | 0 |

`p/supply-chain` is not a registry pack; Semgrep Supply Chain is a separate SCA product,
which OSV-Scanner already covers.

Decision: **do not widen**. The user's own criterion was "do not add packs that return
nothing". p/default's 213 rules already subsume the productive ones. Config change is
`iterationCap` 4 and `turnTimeoutMs` 1200000 (Grok used 768s against a 900s cap in H2).

Expected candidates at the medium bar: **3**, not thirty. p/default gives 7 raw, of which
3 are WARNING (medium) and 4 INFO (low). The 3 are the same ones H2 saw: swarm-toml
prototype pollution, parsers.ts ReDoS, search-tool.ts ReDoS.

## H5: untrusted-input boundaries, ranked

Already harnessed: ledger write, chokepoint, `parseSwarmToml`.

Ranked by value of a bug over cost to harness.

1. **`scrub.ts` `findBlockingSecrets` / `scrubText`** (537 lines, plain string in). Invariant 9.
   A miss puts a credential in an append-only ledger and the exported bundle, where it
   cannot be removed. Unicode lookalike folding, JSON walking, and a line-scanner fallback
   make this the most complex single function in the tree. Highest value, trivial to harness.
2. **`predicate.ts` `parsePredicate` / `evaluatePredicate`** (308 lines, plain string in).
   Input is model-authored directly. Invariant 1 promises unparseable predicates render
   UNVERIFIED and *never abort*, so any crash here is an invariant violation by definition.
   Hand-written tokenizer plus recursive descent. Trivial to harness.
3. **`parsers.ts` `parseLineHits` (lcov) and the TAP/test parsers** (524 lines, plain string).
   The ratchet's measurement layer. The build guide states at length that a bad read here
   buys a test deletion. Trivial to harness.
4. **`unified-diff.ts` `parseUnifiedDiff`** (178 lines, plain string). Parses diffs of
   model-written code; feeds the file set and the ratchet. Trivial to harness.
5. **`bundle.ts` `readBundle` / `replay.ts` `replayBundle`**. Genuinely external: a bundle is
   the export format a third party verifies on another machine. Higher harness cost (needs a
   directory shape rather than one buffer), but this is the artifact the tamper-evidence
   story rests on.

Deliberately **not** worth harnessing:
- `tui/*`: rendering; a crash is visible and costs nothing.
- `select/*` (hardware probe, pricing, shortlist): a crash degrades model choice, no
  security or integrity consequence.
- `derivation.ts`: documented as a tunable heuristic with a false-positive rate, so a
  "wrong" answer is in spec. Nothing to assert.
- `providers/message-conversion.ts`: Zod-validated at the boundary per invariant 10; the
  schema is the check.
- `review-page.ts`: a crash costs nothing and the real risk is HTML injection into a page a
  reviewer opens. That is a property test about escaping, not a fuzz target. Semgrep already
  flags 4 INFO candidates here; see H4.

## H8: dependency exposure

16 direct (9 runtime, 7 dev). **260 lockfile entries: 56 runtime, 204 dev-only.** The
155-package figure predates `@jazzer.js/core`, which I added in H1 and which alone pulls 84.

Subtree attribution: `@jazzer.js/core` 84, `vitest` 42, `ink` 40, `typescript` 20,
`@biomejs/biome` 8, `@ai-sdk/anthropic` 7, `ai` 5, the rest 3 or fewer. `zod`, `smol-toml`
and `react` pull **zero**. The shipped surface is genuinely small; the bulk is test tooling.

Outdated: five packages behind by a **patch only**. One real gap: **`@types/node` 22.20.1
against latest 26.2.0, four majors**, and the runtime is now Node 24. That is the same
mismatch H1a fixed everywhere else.

Install scripts: **exactly one**, `fsevents`, dev-only, the macOS watcher vitest pulls.

Maintenance: everything published within ~5 weeks except `@jazzer.js/core` (2026-04-15,
~4 months). Single-maintainer packages: `smol-toml`, `zod`, `react`. Of these only
`smol-toml` is both single-maintainer and parsing untrusted input, and that path is
already the `swarm-toml` harness.

**Upgrade this:** `@types/node` to 26.x, to match the Node 24 runtime.
**Watch this:** `smol-toml` (single maintainer, untrusted parser, mitigated by the harness);
`@jazzer.js/core` (slowest-moving, largest subtree, dev-only so it never ships).
**Do nothing:** the five patch-level lags; `npm ci` picks them up.

Recommendation: **not** a CROSSFIRE detector. OSV already covers advisories, and "outdated"
and "dormant" are not findings with repros, so they cannot pass the verify gate that makes a
CROSSFIRE finding mean anything. This belongs in the weekly scheduled job as a plain report.

## H4: everything below the medium bar is noise. Bar stays at medium, permanently.

The 4 sub-medium findings are **one construct reported four times**. All are
`detect-replaceall-sanitization` at `src/evidence/review-page.ts:160`, the `escapeHtml`
function. Semgrep matches the `.replaceAll()` chain once per nesting level, so the same
five-line function yields four findings whose quoted "string" grows by one call each time.

The function is correct:

```ts
text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;")
```

`&` is escaped first, which is the ordering that matters, and the five entities cover text
and attribute context. The rule is style advice ("better to use a well known sanitization
lib"), not a defect report.

Verified there is nothing behind it: every template interpolation in the file that is **not**
wrapped in `escapeHtml` is a number (`node.sequence`, `dag.claims.length`, `recordCount`,
`(after * 100).toFixed(1)`), a literal from a boolean, `isoTime(...)` off
`Date.toISOString()`, or the hardcoded `styles` constant. **No model-controlled string
reaches the HTML unescaped.**

Decision: **severityBar stays at medium permanently.** Not re-litigated. The low pass was
not run, because reading the list answered the question the run was meant to answer at zero
API cost, and the user's stated purpose was "to know what is down there", not to fix it.

Side finding worth carrying: those four share one construct but get **four distinct ids**,
because `sastFindingId` keys on the flagged source text and each nesting level yields
different text. At the low bar this single non-defect would buy **four Grok confirmation
turns**. That is a concrete cost argument for the medium bar and a minor dedup weakness in
`identity.ts`: findings whose flagged spans nest inside one another are one defect.

## H6a: a real defect found while building the scrub harness

`src/evidence/scrub.ts`, `classifyValue`, line 173:

```ts
if (value.length < 8) {
  return "not-credential";
}
```

**Any value shorter than eight characters sitting under a credential-bearing name is never
redacted, by either path.** Measured boundary, both `scrubJson` and `scrubText`:

| value | length | result |
|---|---|---|
| `"pw"` | 2 | leaks |
| `"s3cr3t"` | 6 | leaks |
| `"hunter2"` | 7 | leaks |
| `"hunter22"` | 8 | redacted |
| `"Tr0ub4dor"` | 9 | redacted |

`isCredentialName("password")` returns true, so the name is recognised; the value is
discarded on length before the name can matter.

This contradicts two statements in the codebase. Invariant 9 says the detector "keys on the
assignment name or the field name rather than on the shape of the value". The comment above
`classifyValue` says scrubbing "acts on anything but a measurement, since over-redacting
costs nothing", and that the gate/scrub asymmetry "loses a warning, never the redaction".
For a value of seven characters or fewer, the redaction is what is lost.

Cost: a short credential under a field literally named `password` enters an **append-only**
ledger, and the blob directory it lands in is what a bundle export copies to another machine.
There is no removing it afterwards.

Not fixed here. The obvious fix, dropping the length floor in the `named` context only, is a
real false-positive tradeoff over what lands in every record, and the numeric branch above it
shows the author reasoned about exactly this tension. It is recorded for H10 and left as the
owner's call.

## H6b: two harnesses written (build and validation pending)

`fuzz/scrub.fuzz.cjs` + 12 seeds, and `fuzz/predicate.fuzz.cjs` + 15 seeds. Both load from
`../.swarm/fuzz-build/...`, never from `../src`. `fuzz/smoke.mjs` discovers `*.fuzz.cjs`
automatically, so wiring is free; to be confirmed after the build.

Properties asserted, chosen to be genuinely invariant rather than to encode the bug above:
- scrub: never throws; scrubbing is idempotent; the **export scan finds nothing in what the
  write-time scrub produced** (invariant 9's "three sites cannot drift apart", stated as a
  checkable property); the gate blocks on a subset of what the scan reports; the structural
  path leaves no residual and does not mutate its input.
- predicate: parsing settles as a node or as `PredicateParseError` and **never any other
  throw**, which is invariant 1's "unparseable predicates never abort the run" made
  mechanical; evaluation never throws against five payload shapes; every result is a boolean
  verdict or one of two named failures; parsing is deterministic.

Build and coverage validation deferred: `npm run fuzz:build` starts with
`rm -rf .swarm/fuzz-build`, which would pull the build out from under the H3 run's fuzzers.

## H9: recurring run design

### The finding that shapes everything else

Every run so far raised the **same three candidates**, and two of them were dismissed both
times by a fresh Grok turn doing the same work: 106s then 91s for the swarm-toml prototype
pollution, 31s then 23s for the parsers.ts ReDoS. Nothing in the system remembers that a
construct was already argued about.

On a schedule that compounds. A weekly job re-pays for the same two dismissals every week,
forever, and a per-PR job pays for them on every PR. **The recurring run is not economical
until cross-round finding memory exists** (the same mechanism the termination gap needs).
That is why it is the priority work item, and the design below is sized on the assumption
it lands first.

### Trigger: both, with sharply different scope

**Per-PR (cheap, gating-ish).** Semgrep and OSV only, no fuzz, `iterationCap` 1, and
**confirmation only, no fix turn**. Its question is "did this PR introduce a candidate the
mainline did not already have", so it diffs findings against the mainline baseline and
spends a Grok turn only on ids absent from it. On swarm today that is zero turns on almost
every PR, so the run is ~5 seconds of semgrep plus OSV. Fixing is deliberately excluded: a
bot rewriting an author's branch mid-review fights the author.

**Weekly cron (full).** All detectors including fuzz with the accumulated corpus,
`iterationCap` 4, medium bar, fix turns enabled. This is where real spend goes.

### Cost per run, from measured data

| | wall clock | agent turns | transcript volume |
|---|---|---|---|
| per-PR, no new findings | ~5s | 0 | 0 |
| per-PR, one new candidate | ~3 to 13 min | 1 confirmation | ~1MB |
| weekly full, nothing new | ~30 min | 0 with memory, 3 without | 0 / ~3MB |
| weekly full, one real finding | ~45 min | 1 confirm + 1 fix | ~3.5MB |

Measured basis: H2's no-fuzz run spent 91s + 23s + 419s on confirmations and 200s on the
fix, producing a 3.17MB Grok transcript and a 300KB Claude transcript. Fuzz adds a flat 900s
of detection. Grok's confirmation turns are the dominant cost and vary by an order of
magnitude (23s to 768s) depending on how hard it works to build a repro.

Verdict on tolerability: the weekly job is ~30 minutes of wall clock and, **with finding
memory**, zero agent turns in the common case. That is a job worth keeping. Without memory
it is three Grok turns a week to re-derive two dismissals, which is the kind of cost that
gets a job switched off in a month.

### Where results land, and the constraint discovered in H1

**Never the mainline.** Findings and fixes land on `crossfire/findings`, a long-lived branch.

That shape is forced by a real constraint: the repo has an active ruleset (`restrictdelete`,
id 15229475) that restricts ref **creation**. The H1 push of `v13-main` only succeeded via
owner bypass, reporting "Bypassed rule violations". A CI token without bypass **cannot create
a branch**, so a design that cuts `crossfire/<date>` per run fails on its first scheduled
attempt, and fails at push time after all the spend. Committing to one pre-created branch
avoids ref creation entirely. No force-push, ever.

### Notification

- Every run writes a GitHub Actions job summary: detectors run, candidates raised,
  verdicts, and the ledger head hash.
- A **confirmed** finding opens a GitHub issue assigned to the owner. A dismissal does not.
  This is the "gets my attention when a finding is confirmed rather than dismissed"
  requirement, and it is exactly the line the confirmation step already draws.

### Ledger retention and cross-run chain

One ledger per target, appended across runs, committed to `crossfire/findings` alongside the
findings. `crossfire export --ledger <path>` already verifies the chain and exits non-zero
when it breaks, so the scheduled job runs it as its last step and fails loudly on a broken
chain. Retention is then just git history on that branch.

### What I would build first

1. Cross-round finding memory. Everything else is unaffordable without it.
2. The weekly cron, full scope.
3. The per-PR job, once memory makes the baseline diff meaningful.

## Design: cross-round finding memory (priority CROSSFIRE work item)

Two problems observed in this plan are one missing mechanism.

**Problem 1, the termination gap.** `state-machine.ts` ends a run on `open.length === 0`,
where `open` is refreshed only by the fuzz cross-check. Semgrep and OSV are not re-run, so
"clean" means "the findings we already knew about are closed", not golden rule 3's "zero
confirmed findings surviving a full detect-and-verify pass". A residual in a different shape
than the repro tests goes unseen: in H2, had the patch closed only Grok's probe pattern and
left `(\w+)(\w+)$` open, the repro would have flipped and the loop would have declared clean.

**Problem 2, the re-confirmation cost.** A full re-scan is the obvious fix and is unaffordable
as things stand, because some constructs match forever. `detect-non-literal-regexp` still
matches `search-tool.ts` today and always will: constructing a RegExp from model input is
what the tool is for. Re-scanning every round would re-raise it and re-pay a Grok
confirmation turn (measured: 419s and 768s) every round, forever. The same is true of the two
standing dismissals, re-derived at 106s/91s and 31s/23s across two runs.

### The mechanism

Memoize verdicts by finding id, in the ledger, and re-run the full detector suite before
terminating.

The id does the work already and needs no new key. `sastFindingId(rule, file, flaggedSource)`
hashes the rule, the file, and the **whitespace-normalized flagged construct**, with no line
number. So id equality already means "same rule, same file, same construct text". If the
construct changes at all, the id changes, and no stale verdict can transfer to it. Nothing
new has to be digested or stored beside it.

Add one ledger record type, `finding-verdict`: `finding_id`, `verdict` of `dismissed` or
`closed`, the `repro_command` for a closed one, the round, and the sha. It chains like every
other record, so the memory is auditable rather than a cache.

On each detect pass, every raised candidate takes one of four paths:

| prior verdict for this id | action | cost |
|---|---|---|
| none | confirmation turn | one agent turn |
| `dismissed` | carry forward, record as carried | free |
| `closed` | **re-run the repro** | one subprocess |
| any, but id absent from this scan | finding is gone; nothing to do | free |

The `closed` path is the important one and is why this is not a cache. A closed finding is
re-verified **mechanically** every round, never re-confirmed by an agent. If its repro exits
0 again, the fix regressed and the finding reopens as already-confirmed, going straight to a
fix turn with no confirmation spend. That is rule 4 honoured across rounds rather than within
one.

Termination then becomes what rule 3 says: run every detector, resolve every raised candidate
either from memory or by confirmation, re-run every closed repro, and stop when nothing
survives. The common steady-state round costs zero agent turns and a handful of subprocesses.

### The limitation, stated rather than designed away

A carried dismissal is only as good as the reasoning that produced it, and both of swarm's
dismissals are **reachability** arguments: "`name` is never attacker-controlled, every call
site passes a hardcoded literal". The id pins the flagged construct, so an edit *there*
invalidates the verdict. It does not pin the call sites. Adding one caller that passes model
output to `counterPattern` makes that dismissal wrong while its id is unchanged, and the
memory would carry it forward silently.

So dismissals must expire: re-derive after N rounds, or when the file's other contents
change, whichever is cheaper to implement. A closed finding does not need expiry, because its
repro is re-run every round regardless. This asymmetry is the honest one: a mechanical check
can be trusted indefinitely, an argument cannot.

## Found while working: `commitRound` sweeps untracked files into the round commit

`src/broker/git.ts:47`:

```ts
await git(repoPath, ["add", "-A"]);
await git(repoPath, [...IDENTITY, "commit", "--allow-empty", "-q", "-m", message]);
```

`git add -A` stages **everything** in the target working tree, not the files the fix
touched. Any untracked or modified file present at commit time lands in the round commit and
is attributed to CROSSFIRE by the ledger's `git_sha`.

Hit this directly: two harness files and their corpora, written into the target while the H3
run was in its detection phase, would have been swept into H3's round commit had a fix
landed. Moved them out to the scratchpad rather than let it happen; target tree confirmed
clean afterwards.

This matters beyond the accident. Golden rule 5 says every round appends exactly one ledger
entry and one git commit, and the entry attests that commit. If the commit can contain work
the round did not do, the attestation is weaker than it reads, and the fix report's
`files_changed` no longer describes the commit. A concurrent editor, a stray build artifact
that escapes `.gitignore`, or a half-finished edit all contaminate it silently.

The fix is to stage what the fix report named rather than everything: `git add --` over the
union of `files_changed`, and treat anything else in the tree as a dirty-workspace error the
round halts on, which is the fail-closed posture the rest of the system takes. Recorded for
H10 alongside the termination gap.

## H3 run: CROSSFIRE found a real bypass on already-hardened code

One round, clean, exit 0, committed `7343ccf2`. 7 findings detected, 2 dismissed with
substantive reachability arguments (95s and 20s), 1 **confirmed** (408s), fixed by Claude in
624s.

The confirmed one was `search-tool.ts` again, on `v13-main`, which already carried both the
bare and grouped ReDoS fixes. Grok found a genuine bypass:

- **Escape spelling.** `\141+\141+\141+X` is `a+a+a+X` written in octal. The guard read the
  characters the pattern is *spelled with*, not the ones the engine will *match*.
- **Backreference vs octal.** `\1` is a backreference only when the pattern has that many
  capture groups; otherwise it is a legacy octal escape. `countCaptureGroups` now runs before
  the walk.
- **Unprobed atoms read as disjoint.** The probe alphabet was 95 printable characters, so an
  atom matching `\x01` probed to the empty set and `charactersOverlap` returned false, which
  *cleared* the pattern. Disjointness is the answer that lets a pattern run, so it is now
  never the default: an empty probe set is undecided, and the alphabet is all 256 code units.

Exploitability verified, not assumed. `a+a+a+a+a+a+X` and its octal spelling have identical
cost against a failing match: 1ms, 9ms, 51ms, 239ms at n = 20, 30, 40, 50. The guard refused
one and accepted the other.

Graded across 25 patterns both directions: **2 bypasses closed, 0 wrong answers**, all 15
accept-side patterns still accepted.

Fix shipped with **no regression test** again, which led to the root cause below.

## Root cause of the unpinned fixes: the policy forbade what the prompt demanded

The H2 prompt fix was in the running build and did not help. `**/*.test.ts` was in
`excludedPaths`, and `excludedPaths` feeds `createPermissionPolicy`, so the fix agent was
**denied at the filesystem handler** the very file its prompt told it to extend. Verified:
`isExcluded("src/tools/regex-safety.test.ts")` is true.

One list was answering two questions. Removing the glob entirely is wrong: scanning test
files raises 4 ERROR-severity `detected-github-token` findings from fake credentials in scrub
fixtures, all above the medium bar, costing a confirmation turn each.

Fixed in `7d29234`: `scanExcludes` is the scan filter, `excludedPaths` stays the security
boundary, and only the latter reaches the permission policy. Verified end to end against the
swarm config: a test file is not scanned and is writable, a source file is both, `.env` is
neither.

## H6: two harnesses, one real bug

`scrub` and `predicate`, both committed (`999634d5`). Non-blind, measured on a temp copy so
seeds stay clean: **scrub cov 119 ft 285 corp 21**, **predicate cov 139 ft 787 corp 185** over
1.1M executions at 24k/s. `smoke.mjs` discovers both by filename.

Two-sided negative control on `scrub`, after two failed attempts that are worth recording:
`copy["__proto__"] = v` sets the copy's prototype rather than writing to `Object.prototype`,
and scrub's own reconstruction drops `__proto__` before any merge could reach it. Real
pollution needed a deep-merge over the **raw** input, where `JSON.parse` leaves `__proto__` as
an own key. With that injected: detectors on gave `Prototype Pollution`, detectors disabled
gave `AssertionError: scrubbing a payload reached Object.prototype`. Both sides fire
independently. Build restored.

**The scrub harness found a real bug in 30 seconds on clean code**, documented in the coverage
doc and preserved at `fuzz/findings/scrub-nested-multibyte-key.input`.

## H7: corpus persistence, and the budget the curve actually supports

`fuzz/long-run.mjs` (`7324f0fa`). Three distinct directories: committed seeds, accumulated
corpus at `.swarm/fuzz-corpus`, and the temp workspace jazzer is pointed at. The working copy
is folded back only after jazzer exits, so an interrupted run loses new inputs rather than
corrupting what earlier runs found. Crash artifacts are copied to `fuzz/findings` before
cleanup and the run exits non-zero.

One trap worth recording: invoking `npx jazzer` with the temp workspace as cwd exits 0 having
done nothing, because npx resolves binaries from cwd and there is no `node_modules` there. The
run reports a clean pass. The driver invokes the binary by absolute path instead.

Persistence verified across three invocations: 15 inputs to 234 to 569 to 759, seeds untouched
at 15.

**Recommended budget, against the plan's premise of hours per harness: do not.** Edge coverage
was flat from the first 45s pass on every harness (predicate 139/139/139, ledger-chain
107/107, swarm-toml 63/63, adapter-output 183/181), while corpus grew 50x and feature tuples
crept 1 to 5 percent per pass. These are small bounded parsers whose reachable edge set is
exhausted in under a minute. A longer run buys input diversity inside already-covered code,
which is a real but much weaker argument. Sized the run at 600s per harness on that basis,
which is already 13x saturation.
