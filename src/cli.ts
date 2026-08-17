#!/usr/bin/env node
import { existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { createClaudeAgent, createGrokAgent } from "./adapters/index.js";
import type { RunConfig } from "./config/index.js";
import { loadRunConfig } from "./config/index.js";
import type { AgentRunner, DetectorRunner, RunEvent } from "./broker/index.js";
import {
  createAgentRunner,
  createDetectorRunner,
  createDryRunAgents,
  createDryRunDetectors,
  runLoop,
} from "./broker/index.js";
import type { Transcript } from "./obs/index.js";
import { exportLedger, openRunLog, openTranscript } from "./obs/index.js";
import { createPathScope, createPermissionPolicy } from "./policy/index.js";

const USAGE = [
  "crossfire run --config <path> [--dry-run] [--run-dir <dir>]",
  "crossfire resume --config <path> --run-dir <dir> [--dry-run]",
  "crossfire export --ledger <path> [--out <path>]",
  "",
  "run       detect, confirm, analyze, fix, verify, until a mechanical stop",
  "resume    continue the ledger in an existing run directory",
  "export    verify a ledger's chain and print it",
  "",
  "--dry-run stubs the detectors and the agents. The broker, the gates, and the",
  "          ledger still run for real. The target is left alone: a dry run",
  "          records the sha it ran against rather than committing one.",
].join("\n");

export type Out = (text: string) => void;

/** clean is the only outcome that is not something to look at. */
const EXIT_BY_REASON = {
  clean: 0,
  "iteration-cap": 1,
  "test-regression": 1,
  aborted: 1,
} as const;

export async function runCli(
  argv: readonly string[],
  out: Out = (text) => void process.stdout.write(text),
): Promise<number> {
  const [command, ...rest] = argv;

  try {
    switch (command) {
      case "run":
        return await runCommand(rest, out, false);
      case "resume":
        return await runCommand(rest, out, true);
      case "export":
        return exportCommand(rest, out);
      default:
        out(`${USAGE}\n`);
        return 2;
    }
  } catch (error) {
    out(`crossfire: ${(error as Error).message}\n`);
    return 2;
  }
}

async function runCommand(argv: readonly string[], out: Out, resume: boolean): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      config: { type: "string" },
      "run-dir": { type: "string" },
      "dry-run": { type: "boolean", default: false },
    },
  });

  if (values.config === undefined) {
    out(`crossfire: --config is required\n\n${USAGE}\n`);
    return 2;
  }

  const config = loadRunConfig(values.config);
  const runDir = resolve(values["run-dir"] ?? join("runs", stamp()));
  const ledgerPath = join(runDir, "ledger.jsonl");

  if (resume && !existsSync(ledgerPath)) {
    out(`crossfire: ${runDir} holds no ledger to continue\n`);
    return 2;
  }

  const dryRun = values["dry-run"] === true;
  const log = openRunLog(join(runDir, "run.jsonl"));
  const transcripts: Transcript[] = [];

  try {
    const agents = dryRun
      ? createDryRunAgents(join(runDir, "dry-run.marker"))
      : agentConnectors(config, runDir, transcripts);
    const detectors: DetectorRunner = dryRun
      ? createDryRunDetectors(config, join(runDir, "dry-run.marker"))
      : createDetectorRunner(config);

    out(`crossfire: ${config.task}\n`);
    out(`  target ${config.target.repoPath}\n`);
    out(`  run    ${runDir}${dryRun ? " (dry run)" : ""}\n`);

    const result = await runLoop({
      config,
      ledgerPath,
      detectors,
      agents,
      resume,
      dryRun,
      onEvent: (event) => {
        log.write(event);
        const line = describe(event, dryRun);
        if (line !== undefined) {
          out(`${line}\n`);
        }
      },
    });

    return EXIT_BY_REASON[result.reason];
  } finally {
    log.close();
    for (const transcript of transcripts) {
      transcript.close();
    }
  }
}

/**
 * The real agents, each with its permission policy and its own transcript. The
 * policy is what stops Grok writing source; the adapter only decides how the
 * process is launched.
 *
 * These are connectors rather than live handles: the runner spawns an agent for
 * the turn it is about to run and closes it afterwards, so no process waits
 * through the detection phase to be used. The transcript is opened once and
 * outlives the processes writing to it, so a run still reads as one stream per
 * agent rather than one per turn.
 */
function agentConnectors(
  config: RunConfig,
  runDir: string,
  transcripts: Transcript[],
): AgentRunner {
  const scope = createPathScope(config.target.repoPath, config.target.excludedPaths);
  const claudeTranscript = openTranscript(join(runDir, "transcripts", "claude.jsonl"));
  const grokTranscript = openTranscript(join(runDir, "transcripts", "grok.jsonl"));
  transcripts.push(claudeTranscript, grokTranscript);

  return createAgentRunner({
    claude: () =>
      createClaudeAgent({
        cwd: config.target.repoPath,
        policy: createPermissionPolicy("claude", scope),
        hooks: claudeTranscript.hooks,
      }),
    grok: () =>
      createGrokAgent({
        cwd: config.target.repoPath,
        policy: createPermissionPolicy("grok", scope),
        hooks: grokTranscript.hooks,
      }),
  });
}

function exportCommand(argv: readonly string[], out: Out): number {
  const { values } = parseArgs({
    args: [...argv],
    options: { ledger: { type: "string" }, out: { type: "string" } },
  });

  if (values.ledger === undefined) {
    out(`crossfire: --ledger is required\n\n${USAGE}\n`);
    return 2;
  }

  const exported = exportLedger(values.ledger);
  const json = `${JSON.stringify(exported, null, 2)}\n`;

  if (values.out === undefined) {
    out(json);
  } else {
    writeFileSync(resolve(values.out), json);
    out(`crossfire: wrote ${resolve(values.out)}\n`);
  }

  return exported.verification.ok ? 0 : 1;
}

/** One line for the events worth watching a run through. */
function describe(event: RunEvent, dryRun: boolean): string | undefined {
  switch (event.type) {
    case "round-started":
      return `round ${event.round}`;
    case "detected":
      return `  detected ${event.findings.length} finding(s) from ${event.runs
        .map((run) => `${run.detector}:${run.status}`)
        .join(" ")}`;
    case "raised":
      return `  cold hunt raised ${event.findings.length} candidate(s)`;
    case "candidate-verdict":
      return `  candidate ${event.finding_id} ${event.confirmed ? "confirmed" : `dismissed (${event.reason ?? "no reason given"})`}`;
    case "analyzed":
      return `  analyzed ${event.finding_id}, repro ${event.adopted_repro ? "adopted" : "kept from the detector"}`;
    case "turn":
      return `  ${event.subtask} -> ${event.agent} in ${Math.round(event.duration_ms / 1000)}s`;
    case "fixed":
      return `  ${event.report.fixes.length} fix(es) reported`;
    case "built":
      return `  build ${event.status}${event.note === undefined ? "" : `: ${event.note}`}`;
    case "verified":
      return `  verify ${summarize(event.results)}`;
    case "tested":
      return `  tests ${event.result.status}${event.regressed ? " (regression)" : ""}`;
    case "refuzzed":
      return `  re-fuzz found ${event.new_findings.length} new`;
    case "round-committed":
      // A dry run makes no commit, so it reports the sha it read instead.
      return `  ${dryRun ? "ran against" : "committed"} ${event.git_sha.slice(0, 10)}`;
    case "terminated":
      return `crossfire: ${event.reason} after ${event.rounds} round(s)`;
    default:
      return undefined;
  }
}

function summarize(results: readonly { outcome: string }[]): string {
  if (results.length === 0) {
    return "nothing to check";
  }
  const counts = new Map<string, number>();
  for (const result of results) {
    counts.set(result.outcome, (counts.get(result.outcome) ?? 0) + 1);
  }
  return [...counts].map(([outcome, count]) => `${count} ${outcome}`).join(", ");
}

function stamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  process.exitCode = await runCli(process.argv.slice(2));
}
