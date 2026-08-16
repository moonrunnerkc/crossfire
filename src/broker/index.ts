export {
  buildCandidateConfirmationPrompt,
  buildCrashAnalysisPrompt,
  buildFixPrompt,
} from "./prompts.js";
export type { FindingPromptInput, FixPromptInput } from "./prompts.js";

export { BrokerError } from "./errors.js";
export { parseAgentJson } from "./parse.js";
export { assertGitRepo, commitRound, diffSince, headSha } from "./git.js";

export { createAgentRunner } from "./agents.js";
export { createDetectorRunner } from "./detectors.js";
export type { DetectorRunnerOptions } from "./detectors.js";

export { TERMINATION_REASONS, runLoop } from "./state-machine.js";
export type {
  AgentRunner,
  AgentTurn,
  DetectorRunner,
  RunOptions,
  RunResult,
  TerminationReason,
} from "./state-machine.js";
