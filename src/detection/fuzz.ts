import type { FuzzEngine as FuzzEngineId, RunConfig } from "../config/index.js";
import type { DetectorRun, Finding } from "../contracts/index.js";
import { dedupeFindings } from "./identity.js";
import { createJazzerJsEngine } from "./jazzer-js.js";
import { createLibFuzzerEngine } from "./libfuzzer.js";
import { scopeOf } from "./scope.js";
import type { DetectionResult, FuzzEngine } from "./types.js";

/** Fixed so a run is reproducible; override per run when you want variety. */
export const DEFAULT_FUZZ_SEED = 1;

/**
 * Every engine the config schema accepts, and the adapter that runs it. A
 * record rather than a lookup with a fallback, so an engine added to the schema
 * fails to compile here until it either names an adapter or says it has none.
 */
const ENGINE_ADAPTERS: Record<FuzzEngineId, (() => FuzzEngine) | undefined> = {
  libfuzzer: createLibFuzzerEngine,
  "jazzer.js": createJazzerJsEngine,
  "afl++": undefined,
  jazzer: undefined,
  atheris: undefined,
};

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
    const engine = ENGINE_ADAPTERS[harness.engine]?.();
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
