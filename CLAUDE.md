# CROSSFIRE

Deterministic broker that orchestrates two ACP coding agents (Claude Code and Grok Build) in a detect-analyze-fix-verify loop. Deterministic detectors find the bugs, Grok reasons over confirmed signals, Claude patches, and the broker verifies every fix mechanically. The broker owns all control. The agents only execute subtasks routed to them.

## Golden rules (never violate)

1. The broker owns all control flow. Models never decide routing, the next step, or termination. If a prompt asks a model what to do next, that is a bug: move the decision into code.
2. Findings originate from deterministic detectors: fuzzers and scanners. A model reasons over and confirms signals; a model is never the primary detector and never the sole judge of whether a bug is real. Grok reasons over confirmed crashes and confirms scanner candidates by building a working repro. It does not hunt cold in the default loop.
3. Termination is mechanical only: zero confirmed findings surviving a full detect-and-verify pass, the iteration cap, a test-suite regression, or manual abort. Nothing else stops or continues the loop.
4. A finding is unverified until the broker re-runs its repro command and observes the result. The repro normalizes any detector's native output to the convention below.
5. Every round appends exactly one hash-chained ledger entry and one git commit. Prior entries are immutable.
6. Grok gets read plus execute, never source write. No agent's scope includes secrets or `.env`. Enforce this at the ACP permission and filesystem handlers, not in prompt text.
7. Agent calls are stateless from our side: pass the current findings and the diff, never the accumulated transcript.

## Repro convention

A finding's repro is a shell command. Exit 0 means the vulnerability or crash is still present (reproduced). Non-zero means it cannot be reproduced (closed). For a fuzzer finding, the repro wraps the harness plus the minimized crashing input and normalizes the harness's native exit code to this convention. For a scanner finding, the repro is the dynamic proof Grok built to confirm the candidate. The verify gate marks a finding "survived" if and only if its repro exits 0. This is the single source of truth for whether a fix worked.

## Stack

Node 20+ and TypeScript. `@agentclientprotocol/sdk` pinned to the v1 stable entry point; do not import the experimental v2 path, since its wire format can break between SDK releases. `@agentclientprotocol/claude-agent-acp` for the Claude adapter. Grok Build native ACP for the Grok adapter (confirm the launch invocation from `grok --help`, do not assume a flag). Detection layer: Semgrep for SAST, OSV-Scanner for SCA against lockfiles, and a pluggable fuzz-engine interface with a concrete adapter per target language (libFuzzer or AFL++ for C/C++, Jazzer for Java, Atheris for Python). `zod` for all contracts, failing closed on malformed output. `vitest` for tests. `execa` for scoped subprocess runs in the detectors and gates. `git` for per-round commits.

## Engineering posture

Build as a senior engineer judged on what the next maintainer inherits, not on what looks impressive today.

- Simplest correct solution first. Elegance here means the least code that fully and clearly solves the step, not clever code and not a flexible framework. If a plain function does it, do not reach for a class.
- No overengineering. Build exactly what the step's gate requires. No speculative abstraction, no configuration nobody asked for, no premature generalization, no design pattern applied for its own sake. The interface seams already named in the plan (FuzzEngine, Scanner, AgentHandle) are the only sanctioned abstraction points; do not invent more without a concrete second implementation already in hand.
- Avoid tech debt as you go. No dead code, no commented-out code, no untracked TODOs, no stubs left behind a passing gate. One clear responsibility per module. Every added dependency earns a one-line justification in the commit message.
- Optimize only real hotspots. Prefer clarity by default and reach for performance work only where there is an actual cost, which in this system means the fuzzer loop and the subprocess spawning in the gates. Measure before optimizing, and leave the reasoning in a short comment when you do.
- Expert judgment over compliance. If the plan and reality conflict, say so and propose the better path instead of papering over it. Pick the boring, proven approach. Correctness and readability beat showing off.

## Code conventions

- No em dashes anywhere, including prose, code, comments, and docs. Use commas, colons, semicolons, parentheses, or separate sentences.
- Code reads as human-written: specific names, no comments narrating obvious lines, no boilerplate filler.
- Fail closed. Malformed agent output is rejected by schema, never coerced into something usable.
- No silent catch. Errors surface and the loop halts on a bad state rather than continuing.

## Definition of done (every build step)

Named tests for the step pass, the full suite stays green, and types check. The step's acceptance gate in the build plan is met. No dead code, no untracked TODOs, no stub left behind a green gate, and no abstraction beyond the sanctioned seams. Any new dependency is justified in the commit message. A step is not done because it looks right.

## What lives where

`config/` run config schema and loader. `contracts/` zod schemas for findings, fix reports, ledger entries, and normalized agent events. `detection/` the scanner runner, the fuzzer runner, crash deduplication and minimization, and corpus management. `transport/` the ACP client wrapper and the agent handle interface. `adapters/` the Claude and Grok adapters. `router/` the capability table and subtask routing. `policy/` permission scoping and the secret path matcher. `gates/` the verify gate and test gate. `broker/` the state machine, prompt templating, and the optional planner slot. `ledger/` the hash-chained JSONL writer and chain verifier. `obs/` JSON-RPC transcript logging and the run logger. `cli.ts` the entrypoint. `fixtures/vulnerable-repo/` the deliberately insecure integration target, including a fuzz harness with a known crashing input and a known scanner finding.
