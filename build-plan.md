# CROSSFIRE: Build Plan

A deterministic orchestrator that drives Claude Code and Grok Build as two ACP subprocesses, feeds the attack side from real detectors (fuzzers and scanners) instead of letting an LLM hunt cold, routes subtasks to whichever agent is stronger, and runs a detect-analyze-fix-verify loop until a full pass produces nothing that survives mechanical verification.

Ships with a companion `CLAUDE.md` (separate file). That file is the enforced constitution the agent obeys during every build step. This document is the sequenced plan for producing the system. Codename is a placeholder; rename freely.

---

## 1. What Claude Code is building, and the key design decision

A single Node/TypeScript process (the broker) that:

1. Spawns Claude Code and Grok Build each as an ACP agent subprocess and speaks JSON-RPC to both over stdio.
2. Runs deterministic detectors (a fuzz harness plus SAST and SCA scanners) against the target to produce confirmed signals.
3. Has Grok reason over those confirmed signals: root-cause each crash, confirm each scanner candidate by building a working repro, and assess severity.
4. Has Claude patch each confirmed finding.
5. Verifies every fix mechanically by re-running each finding's repro itself, then re-fuzzes the patched build to catch regressions and adjacent bugs.
6. Records every round as a hash-chained ledger entry plus a git commit, producing a tamper-evident receipt of the whole run.

The design decision that shapes everything: the LLM is not the detector. The consistent lesson from the mature systems (AIxCC cyber reasoning systems, DeepMind's CodeMender, OSS-Fuzz repair work like CodeRover-S) is that agents are strong at analyzing and fixing a confirmed bug and weak at deciding what is a real, reachable, exploitable bug. So detection is deterministic and mechanical, and Grok's job starts only once a fuzzer has a crashing input or a scanner has flagged a candidate. Grok never hunts cold in the default loop. This is the difference between a demo and something that bites on real repos.

The agents never talk to each other. They both talk to the broker, and the broker relays.

## 2. Invariants

The enforced, authoritative copy lives in `CLAUDE.md`. The four that most shape the architecture below:

- The broker owns control flow. The model never decides routing, the next step, or when to stop.
- Findings originate from deterministic detectors. A model reasons over and confirms signals; it is never the primary detector.
- Termination is mechanical: zero confirmed findings surviving a full detect-and-verify pass, iteration cap, test regression, or manual abort.
- A finding is not real until the broker re-runs its repro command and confirms it.

## 3. Tech stack and why

- Node 20+ and TypeScript. The mature ACP client libraries are JS, and it matches the target agents' own runtime.
- `@agentclientprotocol/sdk`, stable v1 entry point only. Do not import experimental v2; its wire format can break between releases. Pin the version.
- `@agentclientprotocol/claude-agent-acp` as the Claude adapter binary (wraps the official Claude Agent SDK).
- Grok Build native ACP as the Grok adapter. Confirm the launch invocation from `grok --help` (P8), with a headless `-p` fallback if the ACP surface is too rough in early beta.
- Detection: Semgrep for SAST (language-agnostic, rules-based), OSV-Scanner for SCA against lockfiles (deterministic, the same OSV data model you already know), and a pluggable fuzz-engine interface. Ship one concrete fuzz adapter end to end first (libFuzzer for C/C++ or Atheris for Python, whichever matches your fixture); add Jazzer for Java later.
- `zod` for all contract schemas. Fail closed on malformed agent output.
- `vitest` for tests. Every build step ends green.
- `execa` for scoped subprocess execution in the detectors and gates.
- `simple-git` or shelling to git for per-round commits.

Optional: `@mcpc-tech/acp-ai-provider` exposes ACP agents through a uniform interface and can save writing raw process lifecycle code. Evaluate it in the transport phase.

## 4. Directory layout

```
crossfire/
  CLAUDE.md          delivered separately; place at repo root before P1
  package.json
  tsconfig.json
  src/
    config/          run config schema + loader
    contracts/       zod schemas: finding, fixreport, ledger, agentevent
    detection/       scanner runner, fuzzer runner, crash dedup+minimize, corpus mgmt
    transport/       acp client wrapper, agent handle interface
    adapters/        claude adapter, grok adapter
    router/          capability table + subtask routing
    policy/          permission scoping, secret path matcher
    gates/           verify gate, test gate
    broker/          state machine, prompt templating, planner slot
    ledger/          hash-chained jsonl writer + chain verifier
    obs/             jsonrpc transcript logging, run logger
    cli.ts           entrypoint
  fixtures/
    vulnerable-repo/ insecure target: fuzz harness + known crashing input + known scanner finding
  test/
```

## 5. Sequenced build prompts

Feed these to Claude Code one at a time. Do not batch. Let each pass its acceptance gate and commit before starting the next. Steps marked parallel can be built in either order once their phase opens.

### Phase 0: Scaffold

**P1. Project scaffold, constitution, and run config.**
Place the provided `CLAUDE.md` at the repo root first, then read it; every subsequent step obeys it. Set up the repo: package.json, tsconfig, vitest, lint, and the directory layout above. Implement the run config schema in `config/` with zod: main task, target repo path, in-scope directories, excluded paths (globs defaulting to `.env*` and common secret files), severity bar, iteration cap, per-turn timeout, the target's test command, the detector config (fuzz harness entry points, corpus directories, fuzz engine per language, Semgrep ruleset, OSV-Scanner lockfile paths), and per-detector time budgets. Provide a sample config and a loader that validates on read.
Gate: `CLAUDE.md` is at root; sample config loads and validates; an invalid config is rejected with a clear error; tests green.

### Phase 1: Contracts (parallel with Phases 2 and 3)

**P2. Finding, FixReport, and AgentEvent schemas.**
In `contracts/`, define zod schemas. Finding: id, source (fuzzer, sast, sca, secret), confirmation_state (confirmed, candidate, dismissed), severity, class, file, optional line, description, repro command, expected_secure_behavior, and an optional crash_artifact path for fuzzer findings. FindingsBatch (round, findings array). FixReport (round, agent, fixes array of finding_id + files_changed + summary). A normalized AgentEvent union (text, thinking, tool_call, tool_result, done, error). Add round-trip and malformed-input rejection tests.
Gate: valid payloads parse, malformed payloads throw, round-trip is lossless, and a fuzzer finding without a crash_artifact is rejected.

**P3. Hash-chained ledger.**
In `ledger/`, implement an append-only JSONL writer where each entry carries round metadata, detector run summaries, findings hash, fixes hash, verify results, test result, git sha, the previous entry's hash, and its own entry hash. Add a chain verifier.
Gate: a normal chain verifies; mutating any entry makes verification fail at that entry.

### Phase 2: Detection (parallel with Phases 1 and 3)

**P4. Scanner runner.**
In `detection/`, wrap Semgrep and OSV-Scanner behind a common Scanner interface. Run them against the configured scope, parse their output, and normalize each result into a candidate Finding (confirmation_state = candidate). Deduplicate across scanners. No agent involvement here; this is pure tooling.
Gate: against `fixtures/vulnerable-repo`, the runner surfaces the known scanner finding as a candidate with correct file and class; a clean directory yields none.

**P5. Fuzzer runner.**
In `detection/`, define a FuzzEngine interface and implement one concrete adapter (libFuzzer for C/C++ or Atheris for Python, matching the fixture). Run the configured harness against its corpus within the time budget, capture crashing inputs, deduplicate by crash signature, and minimize each crashing input. Emit each unique crash as a confirmed Finding (confirmation_state = confirmed) with its minimized crash_artifact.
Gate: against the fixture harness, a known crash is discovered, deduplicated, minimized, and emitted as a confirmed finding with a replayable artifact; a fixed harness yields none within budget.

### Phase 3: Transport (parallel with Phases 1 and 2)

**P6. ACP client wrapper.**
In `transport/`, build the client against `@agentclientprotocol/sdk` v1 using the client() API. Spawn a subprocess, wire stdio, register client-side handlers (requestPermission, sessionUpdate, plus filesystem and terminal as needed). Implement open session, send prompt turn, stream and normalize updates into AgentEvent, and cancel. Build a tiny fake ACP echo agent in fixtures to drive this without a real model.
Gate: against the fake agent, the wrapper opens a session, sends a prompt, receives normalized events, and cancels cleanly.

**P7. AgentHandle interface and Claude adapter.**
Define a uniform AgentHandle interface (newSession, prompt returning an async iterable of AgentEvent, cancel, injected permission policy). Implement the Claude adapter spawning `@agentclientprotocol/claude-agent-acp`. Opt into the subagent-transcript client capability so nested Claude subagent activity stays observable.
Gate: interface implemented; an env-flag-guarded smoke test sends a trivial prompt to real Claude Code and gets a well-formed result.

**P8. Grok adapter.**
Implement the Grok adapter behind the same interface. First confirm Grok Build's ACP launch invocation from `grok --help` and its docs; do not assume a flag. If the native ACP surface is unstable, implement the documented fallback: drive `grok -p` headless and adapt its output into AgentEvent, marked as the degraded path.
Gate: interface implemented; env-flag-guarded smoke test returns a well-formed result via whichever path works.

### Phase 4: Policy (parallel)

**P9. Capability router.**
In `router/`, define a typed SubtaskClass enum and a static class-to-agent table. Crash-analysis, scanner-candidate-confirmation, repro-authoring, and exploitability-assessment map to Grok. Fix, refactor, and test-repair map to Claude. Detection is not an agent class; it is deterministic tooling and must not appear in the table. Unknown classes throw.
Gate: routing table unit tests cover every class; detection classes are absent; unknown class is rejected.

**P10. Permission and secret scoping.**
In `policy/`, define per-agent permission policies and a secret/exclusion path matcher. Enforce them inside the ACP client's permission and filesystem handlers so Grok's write attempts on source are refused and neither agent can read or write excluded paths. Fuzzer and scanner subprocesses run under the same exclusion set.
Gate: policy tests pass; a simulated Grok source-write and any excluded-path access are denied at the handler; detectors cannot read excluded paths.

### Phase 5: Gates

**P11. Verify gate.**
In `gates/`, run each finding's repro via execa in a scoped cwd with a timeout. Apply the convention from `CLAUDE.md`: exit 0 means survived (still vulnerable or still crashing), non-zero means closed. For fuzzer findings, the repro replays the minimized crash_artifact through the harness and normalizes the harness exit code. Return per-finding survived/closed; treat timeouts as inconclusive, not silent pass.
Gate: fixture findings with known-reproducing and known-fixed repros classify correctly; a timeout is reported as inconclusive.

**P12. Test gate and re-fuzz cross-check.**
Run the target's configured test command, compare against a captured baseline, and treat any regression as a hard halt. Then add the re-fuzz cross-check: after a fix round, re-run the fuzzer against the patched build for a bounded budget to surface regressions or bugs adjacent to the patch. New crashes enter the next round as confirmed findings.
Gate: green baseline passes; an injected test failure halts; a fix that reopens the crash is caught by the re-fuzz pass as a new confirmed finding.

### Phase 6: Broker

**P13. Prompt templating.**
In `broker/`, write deterministic prompt builders. The crash-analysis prompt gives Grok one confirmed crash plus its artifact and asks for root cause, severity, and a repro command authored to the exit-code convention. The candidate-confirmation prompt gives Grok one scanner candidate and asks it to either produce a working repro (promoting it to confirmed) or dismiss it with a reason. The fix prompt gives Claude the confirmed findings batch and the rule that every repro must be made to fail without touching out-of-scope files. No free generation of control decisions anywhere.
Gate: snapshot tests render stable prompts from fixture inputs for all three templates.

**P14. State machine core (stubbed agents and detectors).**
Implement the phase machine: DETECT, CONFIRM, ANALYZE, FIX, VERIFY, then loop or terminate. Wire the gates, iteration cap, per-turn timeout, per-round git commit, and all four termination conditions. Drive it with stubbed detector output and stubbed agent output, no real tools yet.
Gate: over stubbed rounds, the loop terminates on zero-confirmed-surviving-findings, terminates on the cap, and halts on a test regression, each deterministically and each producing correct ledger entries.

**P15. Wire real detectors and adapters end to end.**
Connect the real scanner and fuzzer runners into DETECT/CONFIRM and the real Claude and Grok adapters through the router into ANALYZE/FIX, including the re-fuzz cross-check on the committed post-fix state each round.
Gate: env-flag-guarded integration run against `fixtures/vulnerable-repo` discovers the seeded crash and scanner finding, drives them through analyze-fix-verify, closes at least the crash, and leaves a verifiable ledger plus one commit per round.

### Phase 7: Supplemental intelligence and ops

**P16. Optional cold-hunt pass and thin planner slot (both flag-gated, off by default).**
Add an optional supplemental pass where Grok hunts for issues the detectors missed, clearly separated from the confirmed-signal loop and off by default; anything it raises must still be confirmed by building a repro before it can enter a fix round, so it can never become the primary detector. Separately add a bounded planner that only summarizes a confirmed-findings batch into a scoped fix-prompt body and never influences routing or termination.
Gate: with both flags off, behavior is identical to P15; with cold-hunt on, its raises are gated through confirmation; with the planner on, output stays schema-valid and control flow is unaffected.

**P17. Observability.**
In `obs/`, log raw JSON-RPC traffic per agent to timestamped transcripts, log detector runs (inputs, crash signatures, scanner output), emit a structured run log, and add a ledger export command.
Gate: a run yields replayable per-agent transcripts, detector logs, and a chain-verifiable ledger export.

**P18. CLI and docs.**
Build `cli.ts`: `crossfire run --config <path>`, a `--dry-run` using stubbed detectors and agents, and `resume` from the last ledger entry. Write the README covering setup, detector config, the repro convention, and the run lifecycle.
Gate: the CLI runs the fixture end to end, `--dry-run` needs no real tools, and `resume` continues from a partial ledger.

## 6. Risks to watch during the build

1. Detection is the hard part now, not orchestration. A fuzz harness has to be written per target and per entry point, corpora need seeding, and coverage-guided fuzzing is nondeterministic. Fix the seed and the time budget for reproducible runs, and accept that a target with no harness gets only scanner-depth coverage.
2. Scanner false positives. Semgrep and SCA flag candidates, not confirmed bugs. That is exactly why candidates go to Grok for repro-confirmation and never straight to fixing; enforce that a candidate cannot enter a fix round without a passing repro.
3. Crash dedup and minimization are easy to get subtly wrong. Distinct stack traces can be the same root bug and identical traces can be different bugs. Dedup by a signature you can defend, and keep the raw artifact so a bad dedup is recoverable.
4. ACP v2 is a moving draft. Stay on v1 stable and pin. Treat any v2 migration as its own deliberate step.
5. Grok Build is early beta, and its ACP surface may be rough. P8's fallback exists for this. Validate Grok in isolation first.
6. Subagent nesting has no standard in ACP 1.2. The Claude adapter opts into the subagent-transcript capability to keep nested activity visible.
7. Credential exposure. Grok Build had repo `.env` credential leakage before mid-July 2026. Excluded paths default to secrets, scoping is enforced at the handler, and detectors run under the same exclusion set. Do not relax this.
8. Context bloat. Never replay the full transcript into an agent turn. Current findings plus diff only.

## 7. How to run the plan

Feed one prompt, let Claude Code build it, confirm the gate, commit, then move on. If a step fails its gate, fix it before proceeding; do not stack unverified work. The order lets contracts, detection, and transport proceed in parallel, then policy and gates, then the broker assembles once its parts each pass in isolation. By P15 you have a working loop against a fixture that finds real crashes with a fuzzer, reasons over them with Grok, fixes with Claude, and verifies mechanically. Everything after hardens it and makes each run its own verifiable evidence.
