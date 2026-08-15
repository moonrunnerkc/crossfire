import type { RunConfig } from "../config/index.js";
import type { DetectorRun, Finding } from "../contracts/index.js";
import { runFuzzers } from "../detection/index.js";

/** Enough to re-walk the patched path, far short of a detection pass budget. */
export const DEFAULT_REFUZZ_BUDGET_MS = 60_000;

export interface RefuzzOptions {
  timeBudgetMs?: number;
  seed?: number;
}

export interface RefuzzOutcome {
  runs: DetectorRun[];
  newFindings: Finding[];
}

/**
 * Re-runs the fuzzer against the patched build for a bounded budget. Anything it
 * turns up that is not already an open finding is news: a bug adjacent to the
 * patch, or the round's own crash reopened by a fix that did not hold. Either
 * way it enters the next round as a confirmed finding, since a crash the fuzzer
 * just reproduced needs no model to vouch for it.
 *
 * Deduplication is against what is still open rather than against everything
 * ever seen, because a crash that was closed and then reintroduced is exactly
 * the regression this pass exists to catch.
 */
export async function refuzzCrossCheck(
  config: RunConfig,
  openFindingIds: readonly string[],
  options: RefuzzOptions = {},
): Promise<RefuzzOutcome> {
  const bounded: RunConfig = {
    ...config,
    detectors: {
      ...config.detectors,
      fuzz: {
        ...config.detectors.fuzz,
        timeBudgetMs: options.timeBudgetMs ?? DEFAULT_REFUZZ_BUDGET_MS,
      },
    },
  };

  const result = await runFuzzers(bounded, {
    ...(options.seed === undefined ? {} : { seed: options.seed }),
  });
  const open = new Set(openFindingIds);

  return {
    runs: result.runs,
    newFindings: result.findings.filter((finding) => !open.has(finding.id)),
  };
}
