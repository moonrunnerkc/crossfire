# Contributing

The rules this repo is built under are in [CLAUDE.md](CLAUDE.md). Read those first; this file is the mechanics.

## Setup

```sh
git clone git@github.com:moonrunnerkc/crossfire.git
cd crossfire
npm install
npm run check
```

Node 20 or newer. Nothing else is needed to work on crossfire itself: the detector binaries and the agent CLIs only matter when you run against a real target.

## The dev loop

| Command | What it does |
| --- | --- |
| `npm run typecheck` | `tsc --noEmit`, strict, with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` on |
| `npm run lint` | ESLint over everything but `dist/`, `node_modules/`, `fixtures/`, and `runs/` |
| `npm test` | `vitest run`, the whole suite |
| `npm run test:watch` | vitest in watch mode |
| `npm run check` | all three, in that order. This is the gate |
| `npm run build` | `tsc -p tsconfig.build.json` into `dist/` |

Two test files are guarded because they spawn the real agents and spend real tokens:

```sh
CROSSFIRE_SMOKE=1 npx vitest run test/smoke.test.ts
CROSSFIRE_INTEGRATION=1 npx vitest run test/integration.test.ts
```

The smoke tests ask each agent for one word over ACP. The integration test drives the CLI through a full loop against a temp copy of `fixtures/vulnerable-repo`, takes about seven minutes, and needs semgrep, osv-scanner, a clang carrying the libFuzzer runtime, and both agent CLIs logged in. Run at least the smoke tests before touching anything in `transport/` or `adapters/`.

The prompt builders are snapshot tested. If you change a prompt on purpose, update the snapshot and read the diff before you commit it:

```sh
npx vitest run test/prompts.test.ts -u
```

## Conventions the tests enforce

- **No em dashes.** `test/conventions.test.ts` walks every tracked file and fails on one. Commas, colons, semicolons, parentheses, or two sentences.
- **Type-only imports are explicit.** `@typescript-eslint/consistent-type-imports` is an error, so `import type { Finding }` rather than a plain import.
- **No empty catch.** `no-empty` with `allowEmptyCatch: false`. If you swallow an error, the block has to say why in a comment, and it had better be a good reason.
- **Unused arguments are prefixed with `_`.** Everything else unused is an error.

Beyond that: fail closed on malformed input, don't coerce a bad shape into a usable one, and let a bad state halt the loop rather than continuing quietly.

## Where things go

Adding to crossfire usually means one of these, and each has an existing shape to copy:

- **A fuzz engine.** Implement `FuzzEngine` in `detection/`, then add it to `engineFor` in `detection/fuzz.ts`. `libfuzzer.ts` is the reference, including how a crash is deduplicated, minimized, and proved to replay before it ships as a finding.
- **A scanner.** Implement `Scanner`, then add it to the list in `detection/scan.ts`. Normalize the tool's output into `Finding` with a repro that follows the exit-code convention, and record failures as a `DetectorRun` with a note rather than throwing.
- **A subtask.** Add it to `SUBTASK_CLASSES` and `ROUTING_TABLE` in `router/capabilities.ts`, write its prompt builder in `broker/prompts.ts`, and add its response schema to `contracts/`. If the new prompt asks a model what should happen next, it's the wrong change: that decision belongs in the state machine.

Don't add an abstraction seam that isn't `FuzzEngine`, `Scanner`, or `AgentHandle` without a second implementation already in hand.

## Branches and commits

History is linear on `main`, one commit per coherent step of work. Branch if you like, but rebase rather than merge, and don't split a step across commits that each leave the suite red.

Commit messages follow what's already there. The subject is a short capitalized phrase naming the step, no type prefix and no trailing period:

```text
Cold hunt pass and planner slot, both off by default
Gates: verify, test regression, and the re-fuzz cross-check
```

The body is prose, not bullets. It explains the decisions the diff can't: what you chose, what you rejected, and what a check actually proved rather than what it was supposed to prove. Every commit ends with the dependency line, either `No new dependencies.` or one line justifying each addition. That line is required by CLAUDE.md and it's the cheapest place to catch a dependency nobody needs.

## Before you open a PR

`npm run check` has to be green, and so does whatever guarded test covers the area you touched. Say in the PR what you ran, including the guarded runs, and what the result was. "Should work" isn't a result.

A reviewer is going to ask three questions, so answer them first:

1. Does this move a decision out of code and into a prompt? If a model now influences routing, ordering, or whether the loop continues, it's a bug regardless of how well it reads.
2. Is a finding still unverified until the broker ran its repro? Anything that takes an agent's word for a result is the same bug in a different place.
3. Is there anything left behind: dead code, a commented-out block, a TODO with no owner, a stub sitting behind a green test?
