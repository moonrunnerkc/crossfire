# CROSSFIRE: Build Prompts

Seven prompts. Feed one per Claude Code turn. Each one assumes `CLAUDE.md` and `build-plan.md` are in the repo root, and tells the agent to read the relevant section rather than restating it, so the prompts stay short without losing the detail. After each gate passes, commit, then send the next.

The engineering posture in CLAUDE.md (senior engineer, tech-debt-averse, no overengineering, simplest correct solution, optimize only real hotspots) governs every prompt below. It is loaded and adopted in BP1 and applies to all seven, so the later prompts do not repeat it.

Order: BP1 first. BP2, BP3, and BP4 can run in any order once BP1 is done. Then BP5, BP6, BP7 in sequence.

If BP3 or BP5 feels too large in one turn, split it at the sub-deliverable boundaries called out inside it; nothing else needs splitting.

---

## BP1: Foundations

Read `CLAUDE.md` in full, then build-plan.md Phase 0 and Phase 1. Adopt the Engineering posture in CLAUDE.md as your operating standard for this step and every step after it, and treat its Definition of Done, including the no-dead-code, no-untracked-TODOs, and no-abstraction-beyond-sanctioned-seams checks, as gating on every commit. Obey CLAUDE.md for every decision. Build, in order: the project scaffold and directory layout, the run config schema and loader in `config/` (including detector config and time budgets), the contract schemas in `contracts/` (Finding with source and confirmation_state and optional crash_artifact, FindingsBatch, FixReport, AgentEvent), and the hash-chained append-only ledger in `ledger/` with a chain verifier. Follow the Definition of Done in CLAUDE.md.

Gate: CLAUDE.md is at root and honored; a sample config validates and an invalid one is rejected with a clear error; contract schemas parse valid payloads, reject malformed ones, round-trip losslessly, and reject a fuzzer finding with no crash_artifact; the ledger chain verifies and fails at any mutated entry; full suite green. Commit.

## BP2: Detection

Read build-plan.md Phase 2. Build the `detection/` layer: a Scanner interface wrapping Semgrep (SAST) and OSV-Scanner (SCA) that normalizes results into candidate Findings and deduplicates across scanners, and a FuzzEngine interface with one concrete adapter matching the fixture (libFuzzer for C/C++ or Atheris for Python) that runs the harness within budget, captures and deduplicates and minimizes crashing inputs, and emits each unique crash as a confirmed Finding with its minimized artifact. No agent involvement here; this is deterministic tooling. Seed `fixtures/vulnerable-repo` with a fuzz harness, a known crashing input, and a known scanner finding as part of this step.

Gate: against the fixture, the scanner surfaces the known finding as a candidate with correct file and class, a clean directory yields none; the fuzzer discovers, deduplicates, minimizes, and emits the known crash with a replayable artifact, and a fixed harness yields none within budget; suite green. Commit.

## BP3: Transport and scoping

Read build-plan.md Phase 3 and step P10 of Phase 4. Build `transport/` and `adapters/` and the scoping half of `policy/`. Deliverables, in order: (1) the ACP client wrapper against `@agentclientprotocol/sdk` v1 with client-side handlers and normalized AgentEvent streaming, driven in tests by a fake ACP echo agent; (2) the uniform AgentHandle interface and the Claude adapter over `@agentclientprotocol/claude-agent-acp` with the subagent-transcript capability opted in; (3) the Grok adapter behind the same interface, confirming the launch invocation from `grok --help` first and using the headless `-p` fallback if native ACP is unstable; (4) per-agent permission policies and the secret/exclusion path matcher enforced inside the client's permission and filesystem handlers, with detector subprocesses under the same exclusion set. Split points if needed are between these four.

Gate: against the fake agent the wrapper opens a session, sends a prompt, streams normalized events, and cancels; env-flag-guarded smoke tests return well-formed results from real Claude and from Grok via whichever path works; a simulated Grok source-write and any excluded-path access are denied at the handler; suite green. Commit.

## BP4: Gates

Read build-plan.md Phase 5. Build `gates/`: the verify gate that runs each finding's repro under a timeout and applies the CLAUDE.md exit-code convention (exit 0 means survived), replaying the minimized crash_artifact through the harness for fuzzer findings and treating timeouts as inconclusive; and the test gate that runs the target's test command against a captured baseline and halts on regression, plus the re-fuzz cross-check that re-runs the fuzzer on the patched build for a bounded budget and feeds any new crash into the next round as a confirmed finding.

Gate: fixture findings with known-reproducing and known-fixed repros classify correctly and a timeout reports inconclusive; a green baseline passes and an injected test failure halts; a fix that reopens the crash is caught by the re-fuzz pass as a new confirmed finding; suite green. Commit.

## BP5: Broker brain

Read build-plan.md step P9 of Phase 4 and Phase 6 steps P13 and P14. Build the capability router in `router/` (crash-analysis, candidate-confirmation, repro-authoring, and exploitability-assessment to Grok; fix, refactor, test-repair to Claude; detection is not an agent class; unknown throws), the three deterministic prompt templates in `broker/` (crash-analysis, candidate-confirmation, fix), and the state machine core (DETECT, CONFIRM, ANALYZE, FIX, VERIFY, loop or terminate) wired to the gates with the iteration cap, per-turn timeout, per-round commit, and all four termination conditions, driven entirely by stubbed detector and agent output. Split point if needed is between the router-plus-templates and the state machine.

Gate: router tests cover every class, detection classes are absent, unknown is rejected; prompt snapshots are stable for all three templates; over stubbed rounds the loop terminates on zero-confirmed-surviving-findings, terminates on the cap, and halts on a test regression, each deterministically and each writing correct ledger entries; suite green. Commit.

## BP6: Integration

Read build-plan.md step P15 of Phase 6. Replace the stubs from BP5: wire the real scanner and fuzzer runners into DETECT and CONFIRM, and the real Claude and Grok adapters through the router into ANALYZE and FIX, including the re-fuzz cross-check on the committed post-fix state each round. Keep it env-flag-guarded so it does not run in the normal test suite.

Gate: the guarded integration run against `fixtures/vulnerable-repo` discovers the seeded crash and scanner finding, drives them through analyze-fix-verify, closes at least the crash, and leaves a verifiable ledger with one commit per round; the normal suite still runs without real tools or models. Commit.

## BP7: Supplemental intelligence and ops

Read build-plan.md Phase 7. Build the flag-gated extras and the operational surface: the optional cold-hunt pass (off by default, its raises gated through repro-confirmation so it can never become the primary detector) and the bounded planner slot (only summarizes a confirmed-findings batch into a fix-prompt body, never touches routing or termination); the observability in `obs/` (per-agent JSON-RPC transcripts, detector logs, structured run log, ledger export); and `cli.ts` with `run --config`, `--dry-run` on stubbed detectors and agents, and `resume` from the last ledger entry, plus the README.

Gate: with both flags off, behavior matches BP6; cold-hunt raises are gated through confirmation and the planner leaves control flow unaffected and output schema-valid; a run yields replayable transcripts, detector logs, and a chain-verifiable ledger export; the CLI runs the fixture end to end, `--dry-run` needs no real tools, and `resume` continues from a partial ledger; suite green. Commit.
