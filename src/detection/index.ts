export { runTool, shellQuote } from "./exec.js";
export type { RunToolOptions, ToolResult } from "./exec.js";

export {
  dedupeFindings,
  findingId,
  fuzzFindingId,
  sastFindingId,
  scaFindingId,
  toSlug,
} from "./identity.js";
export type { DedupeResult } from "./identity.js";

export { createSemgrepScanner, normalizeSemgrepOutput } from "./semgrep.js";
export { createOsvScanner, normalizeOsvOutput } from "./osv-scanner.js";
export { runScanners } from "./scan.js";
export { partitionByScope, scopeOf } from "./scope.js";

export { parseCrashReport, resolveRepoFile } from "./crash-report.js";
export type { CrashFrame, CrashReport } from "./crash-report.js";
export { CRASH_ARTIFACT_DIR, createLibFuzzerEngine } from "./libfuzzer.js";
export { DEFAULT_FUZZ_SEED, runFuzzers } from "./fuzz.js";

export type {
  DetectionResult,
  DetectionScope,
  DetectorOutcome,
  FuzzEngine,
  FuzzJob,
  Scanner,
} from "./types.js";
