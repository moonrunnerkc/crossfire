import type { RunConfig } from "../config/index.js";
import type { DetectorRun, Finding } from "../contracts/index.js";
import type { DetectionResult } from "../detection/index.js";
import { dedupeFindings, runFuzzers, runScanners } from "../detection/index.js";
import type { RefuzzOutcome } from "../gates/index.js";
import { DEFAULT_REFUZZ_BUDGET_MS, refuzzCrossCheck } from "../gates/index.js";
import type { DetectorRunner } from "./state-machine.js";

export interface DetectorRunnerOptions {
  /** The bounded budget for the post-fix cross-check, well under a detection pass. */
  refuzzBudgetMs?: number;
  /** Fixed so a run is reproducible, per the plan's note on fuzzing. */
  seed?: number;
}

/**
 * The real detection layer behind the broker's seam: scanners and fuzzers, run
 * against the configured scope, deduplicated into one set of findings. Scanners
 * emit candidates and the fuzzer emits confirmed crashes, which is the whole of
 * why one goes on to CONFIRM and the other straight to ANALYZE.
 */
export function createDetectorRunner(
  config: RunConfig,
  options: DetectorRunnerOptions = {},
): DetectorRunner {
  const seed = options.seed;

  return {
    async detect(): Promise<DetectionResult> {
      // Scanners first: they are cheap, and running them in a fixed order keeps
      // a round's findings hash independent of scheduling.
      const scanned = await runScanners(config);
      const fuzzed = await runFuzzers(config, seed === undefined ? {} : { seed });

      const runs: DetectorRun[] = [...scanned.runs, ...fuzzed.runs];
      const collected: Finding[] = [...scanned.findings, ...fuzzed.findings];
      const { findings, duplicatesDropped } = dedupeFindings(collected);

      return {
        runs,
        findings,
        duplicatesDropped:
          scanned.duplicatesDropped + fuzzed.duplicatesDropped + duplicatesDropped,
      };
    },

    refuzz(openFindingIds: readonly string[]): Promise<RefuzzOutcome> {
      return refuzzCrossCheck(config, openFindingIds, {
        timeBudgetMs: options.refuzzBudgetMs ?? DEFAULT_REFUZZ_BUDGET_MS,
        ...(seed === undefined ? {} : { seed }),
      });
    },
  };
}
