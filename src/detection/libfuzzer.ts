import { existsSync } from "node:fs";
import { resolve } from "node:path";

import type { Severity } from "../contracts/index.js";
import { parseCrashReport, toPosix } from "./crash-report.js";
import { shellQuote } from "./exec.js";
import type { EngineCommand, LibFuzzerTarget } from "./libfuzzer-driver.js";
import { INPUT_TIMEOUT_SECONDS, libFuzzerDriver } from "./libfuzzer-driver.js";
import type { FuzzEngine, FuzzJob } from "./types.js";

const SEVERITY_BY_KIND: Record<string, Severity> = {
  "heap-use-after-free": "critical",
  "double-free": "critical",
  "heap-buffer-overflow": "high",
  "stack-buffer-overflow": "high",
  "global-buffer-overflow": "high",
  "dynamic-stack-buffer-overflow": "high",
  "use-after-poison": "high",
  "attempting-free-on-address-which-was-not-malloc": "high",
  segv: "high",
  "deadly-signal": "high",
  "stack-overflow": "medium",
  "out-of-memory": "medium",
  timeout: "medium",
  "detected-memory-leaks": "medium",
};

export function createLibFuzzerEngine(): FuzzEngine {
  return libFuzzerDriver(LIBFUZZER);
}

const LIBFUZZER: LibFuzzerTarget = {
  id: "libfuzzer",

  unrunnable(job: FuzzJob): string | undefined {
    return existsSync(binaryOf(job))
      ? undefined
      : `harness binary ${job.harness.entryPoint} is not built`;
  },

  command(job: FuzzJob, flags: readonly string[], inputs: readonly string[]): EngineCommand {
    return {
      file: binaryOf(job),
      args: [`-timeout=${INPUT_TIMEOUT_SECONDS}`, ...flags, ...inputs],
    };
  },

  parseReport: parseCrashReport,

  severityByKind: SEVERITY_BY_KIND,

  reproCommand(job: FuzzJob, artifactRel: string): string {
    const harness = shellQuote(`./${toPosix(job.harness.entryPoint)}`);
    return `! ${harness} -timeout=${INPUT_TIMEOUT_SECONDS} ${shellQuote(artifactRel)}`;
  },
};

function binaryOf(job: FuzzJob): string {
  return resolve(job.scope.repoPath, job.harness.entryPoint);
}
