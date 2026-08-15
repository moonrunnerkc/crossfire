import type { FuzzEngine as FuzzEngineId, RunConfig } from "../config/index.js";
import type { DetectorRun, Finding } from "../contracts/index.js";
import { dedupeFindings } from "./identity.js";
import { createLibFuzzerEngine } from "./libfuzzer.js";
import { scopeOf } from "./scan.js";
import type { DetectionResult, FuzzEngine } from "./types.js";

/** Fixed so a run is reproducible; override per run when you want variety. */
export const DEFAULT_FUZZ_SEED = 1;

function engineFor(engine: FuzzEngineId): FuzzEngine | undefined {
  return engine === "libfuzzer" ? createLibFuzzerEngine() : undefined;
}

/**
 * Runs every configured harness within the fuzz budget and returns the crashes
 * as confirmed findings. The budget is a detector level one, so harnesses split
 * it evenly rather than each getting the whole thing.
 */
export async function runFuzzers(
  config: RunConfig,
  options: { seed?: number } = {},
): Promise<DetectionResult> {
  const fuzz = config.detectors.fuzz;
  if (!fuzz.enabled) {
    return {
      runs: [
        {
          detector: "fuzz",
          status: "skipped",
          duration_ms: 0,
          findings_emitted: 0,
          note: "disabled in the run config",
        },
      ],
      findings: [],
      duplicatesDropped: 0,
    };
  }

  const scope = scopeOf(config);
  const seed = options.seed ?? DEFAULT_FUZZ_SEED;
  const timeBudgetMs = Math.floor(fuzz.timeBudgetMs / fuzz.harnesses.length);
  const runs: DetectorRun[] = [];
  const collected: Finding[] = [];

  for (const harness of fuzz.harnesses) {
    const engine = engineFor(harness.engine);
    if (engine === undefined) {
      runs.push({
        detector: "fuzz",
        harness_id: harness.id,
        status: "error",
        duration_ms: 0,
        findings_emitted: 0,
        note: `no fuzz engine adapter for ${harness.engine}`,
      });
      continue;
    }

    const outcome = await engine.fuzz({ harness, scope, timeBudgetMs, seed });
    runs.push(outcome.run);
    collected.push(...outcome.findings);
  }

  const { findings, duplicatesDropped } = dedupeFindings(collected);
  return { runs, findings, duplicatesDropped };
}
