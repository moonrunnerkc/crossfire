import type { RunConfig } from "../config/index.js";
import type { Finding, FindingsBatch } from "../contracts/index.js";
import { COLD_HUNT_MAX_RAISES, FIX_PLAN_MAX_CHARS } from "../contracts/index.js";
import { routeSubtask } from "../router/index.js";

/**
 * Every prompt in this file is a pure function of the round's data. Nothing here
 * asks a model what to do next, which agent should take something, or whether
 * the loop should keep going: those are the broker's, and a prompt that asks for
 * one would be a control decision handed to a model.
 */

const REPRO_CONVENTION = [
  "The repro command convention (the broker runs the command and reads only its exit code):",
  "  exit 0 means the bug is still present",
  "  any non-zero exit means the bug is gone",
  "It must be deterministic, take no arguments, and run from the repository root.",
].join("\n");

const READ_EXECUTE_ACCESS = [
  "You have read and execute access to the repository. You cannot write source;",
  "a separate agent applies fixes. Paths outside the in scope directories are",
  "refused by the broker rather than by you.",
].join("\n");

function runHeader(config: RunConfig): string {
  return [
    `Run: ${config.task}`,
    `In scope directories: ${config.target.inScopeDirs.join(", ")}`,
    "Working directory: the target repository root. Every path below is relative to it.",
  ].join("\n");
}

function location(finding: Finding): string {
  return finding.line === undefined ? finding.file : `${finding.file}:${finding.line}`;
}

export interface FindingPromptInput {
  config: RunConfig;
  finding: Finding;
}

export function buildCrashAnalysisPrompt(input: FindingPromptInput): string {
  const { config, finding } = input;

  return [
    "You are analyzing one confirmed crash in the target repository.",
    "A fuzzer already reproduced it from the recorded input, so whether it is real is settled.",
    "",
    runHeader(config),
    "",
    "Crash",
    `  finding id: ${finding.id}`,
    `  class: ${finding.class}`,
    `  severity as detected: ${finding.severity}`,
    `  location: ${location(finding)}`,
    `  crash artifact: ${finding.crash_artifact ?? "none recorded"}`,
    `  detector repro: ${finding.repro_command}`,
    `  what the detector recorded: ${finding.description}`,
    "",
    "Do this",
    "1. Read the code at the crash site and the frames around it.",
    "2. Replay the crash artifact through the harness with the detector repro above.",
    "3. Work out the root cause: the specific defect, not the symptom the sanitizer printed.",
    "4. Author the repro command the broker will use to check every future fix of this crash.",
    "",
    REPRO_CONVENTION,
    "",
    READ_EXECUTE_ACCESS,
    "",
    "Answer with one JSON object and nothing else:",
    "{",
    `  "finding_id": "${finding.id}",`,
    '  "root_cause": "the defect, in one or two sentences",',
    '  "severity": "info | low | medium | high | critical",',
    '  "repro_command": "a shell command following the convention above",',
    '  "expected_secure_behavior": "what the code should do with this input instead"',
    "}",
  ].join("\n");
}

export function buildCandidateConfirmationPrompt(input: FindingPromptInput): string {
  const { config, finding } = input;

  return [
    "You are confirming or dismissing one scanner candidate in the target repository.",
    "A static scanner matched a pattern here. A pattern is not proof, so this is a",
    "candidate until a repro demonstrates it.",
    "",
    runHeader(config),
    "",
    "Candidate",
    `  finding id: ${finding.id}`,
    `  class: ${finding.class}`,
    `  severity as reported: ${finding.severity}`,
    `  location: ${location(finding)}`,
    `  what the scanner flagged: ${finding.description}`,
    "",
    "Do this",
    "1. Read the flagged code and decide whether the defect is reachable with input the program accepts.",
    "2. If it is reachable, build a command that demonstrates it and run that command to check it fails today.",
    "3. If it is not reachable, or the scanner matched something that is not a defect, dismiss it and say why.",
    "",
    REPRO_CONVENTION,
    "The broker runs your repro command itself before this candidate can enter a",
    "fix round. A command that does not exit 0 against the code as it stands",
    "dismisses the candidate, whatever the verdict below says.",
    "",
    READ_EXECUTE_ACCESS,
    "",
    "Answer with one JSON object and nothing else.",
    "To confirm:",
    "{",
    '  "status": "confirmed",',
    `  "finding_id": "${finding.id}",`,
    '  "severity": "info | low | medium | high | critical",',
    '  "repro_command": "a shell command following the convention above",',
    '  "expected_secure_behavior": "what the code should do instead"',
    "}",
    "To dismiss:",
    "{",
    '  "status": "dismissed",',
    `  "finding_id": "${finding.id}",`,
    '  "reason": "why this candidate is not a reachable defect"',
    "}",
  ].join("\n");
}

export interface FixPromptInput {
  config: RunConfig;
  batch: FindingsBatch;
  /** What earlier rounds already changed. Omitted on the first round. */
  diff?: string;
  /** The planner slot's summary, when that flag is on. Context, never instruction. */
  plan?: string;
}

export function buildFixPrompt(input: FixPromptInput): string {
  const { config, batch, diff, plan } = input;
  const findings = batch.findings.flatMap((finding, index) => [
    ...(index === 0 ? [] : [""]),
    `${index + 1}. ${finding.id}  ${finding.class}  severity ${finding.severity}`,
    `   location: ${location(finding)}`,
    `   what it is: ${finding.description}`,
    `   repro: ${finding.repro_command}`,
    `   expected secure behavior: ${finding.expected_secure_behavior}`,
    ...(finding.crash_artifact === undefined
      ? []
      : [`   crash artifact: ${finding.crash_artifact}`]),
  ]);

  return [
    "You are fixing confirmed findings in the target repository.",
    "Each one below was reproduced mechanically: its repro command exits 0 today",
    "because the defect is present.",
    "",
    runHeader(config),
    `Round: ${batch.round}`,
    "",
    `Findings (${batch.findings.length})`,
    ...findings,
    ...(plan === undefined
      ? []
      : ["", "How these relate (summary from the analysis agent, context only):", plan]),
    "",
    "What done means",
    "Every repro command above must exit non-zero after your change, and the",
    `target's own test suite must still pass: ${config.target.testCommand}`,
    "The broker re-runs each repro and that suite itself, so a fix that does not",
    "flip its repro does not count, however well it reads.",
    "",
    "Constraints",
    "- Change only files under the in scope directories.",
    "- Do not weaken or delete a repro, a test, or a harness to make a check pass.",
    "- Fix the defect the finding describes, not the symptom its repro happens to trip.",
    "- Leave findings that are not listed above alone.",
    ...(diff === undefined ? [] : ["", "Changes earlier rounds already made (git diff):", diff]),
    "",
    "Answer with one JSON object and nothing else:",
    "{",
    `  "round": ${batch.round},`,
    `  "agent": "${routeSubtask("fix")}",`,
    '  "fixes": [',
    "    {",
    '      "finding_id": "the id of the finding this fix closes",',
    '      "files_changed": ["paths you edited"],',
    '      "summary": "what you changed and why it closes the finding"',
    "    }",
    "  ]",
    "}",
  ].join("\n");
}

export interface ColdHuntPromptInput {
  config: RunConfig;
  /** What the detectors already hold, so the pass spends its turn elsewhere. */
  known: readonly Finding[];
}

/**
 * The supplemental pass, off unless a run turns it on. It is deliberately framed
 * as raising candidates rather than finding bugs: nothing here reaches a fix
 * round without a repro the broker runs, so this pass cannot become the thing
 * that decides what is real.
 */
export function buildColdHuntPrompt(input: ColdHuntPromptInput): string {
  const { config, known } = input;
  const alreadyHeld =
    known.length === 0
      ? ["  nothing yet this round"]
      : known.map((finding) => `  ${finding.id}  ${finding.class}  ${location(finding)}`);

  return [
    "You are reading this target for defects its detectors did not surface.",
    "A fuzzer and static scanners have already run. This pass is supplemental:",
    "what you raise becomes a candidate, not a finding.",
    "",
    runHeader(config),
    "",
    "Already held, so look elsewhere",
    ...alreadyHeld,
    "",
    "Do this",
    "1. Read the in scope code for defects a fuzzer would not reach and a pattern scanner would not match.",
    "2. Prefer one raise you can argue for over a list you cannot.",
    "3. Raise nothing you would not expect to be able to demonstrate.",
    "",
    "Each raise is put to you again in a separate turn, where you have to produce",
    "a repro command that the broker runs. A raise nobody can reproduce is dropped",
    `and never reaches a fix round. Raise at most ${COLD_HUNT_MAX_RAISES}.`,
    "",
    READ_EXECUTE_ACCESS,
    "",
    "Answer with one JSON object and nothing else:",
    "{",
    '  "raises": [',
    "    {",
    '      "class": "the bug category, for example command-injection",',
    '      "file": "a path relative to the repository root",',
    '      "line": 42,',
    '      "severity": "info | low | medium | high | critical",',
    '      "description": "the defect and how input reaches it",',
    '      "expected_secure_behavior": "what the code should do instead"',
    "    }",
    "  ]",
    "}",
    "An empty raises array is a complete answer.",
  ].join("\n");
}

export interface FixPlanPromptInput {
  config: RunConfig;
  batch: FindingsBatch;
}

/**
 * The planner slot, off unless a run turns it on. It writes one paragraph of a
 * fix prompt. It is not asked what to fix first, what to skip, or whether the
 * run should continue, because those are the broker's and asking would make them
 * negotiable.
 */
export function buildFixPlanPrompt(input: FixPlanPromptInput): string {
  const { config, batch } = input;
  const findings = batch.findings.map(
    (finding) =>
      `  ${finding.id}  ${finding.class}  severity ${finding.severity}  at ${location(finding)}: ${finding.description}`,
  );

  return [
    "You are writing one paragraph for another agent, which is about to fix the",
    "findings below. Every one of them is confirmed and every one of them is being",
    "fixed in this round.",
    "",
    runHeader(config),
    `Round: ${batch.round}`,
    "",
    `Findings (${batch.findings.length})`,
    ...findings,
    "",
    "Write a summary of how these findings relate to each other: shared root",
    "causes, a single change that would close several, and anything about the code",
    "that makes one of them subtler than it looks.",
    "",
    `Keep it under ${FIX_PLAN_MAX_CHARS} characters. Do not restate the list, do not`,
    "rank the work, and do not name a next step.",
    "",
    "Answer with one JSON object and nothing else:",
    "{",
    `  "round": ${batch.round},`,
    '  "summary": "the paragraph"',
    "}",
  ].join("\n");
}
