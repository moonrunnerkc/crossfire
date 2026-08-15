import type { FuzzEngine as FuzzEngineId, FuzzHarnessConfig } from "../config/index.js";
import type { DetectorRun, Finding } from "../contracts/index.js";

/** The slice of the target a detector is allowed to look at. */
export interface DetectionScope {
  repoPath: string;
  inScopeDirs: readonly string[];
  excludedPaths: readonly string[];
}

/**
 * What every detector returns: the findings it produced plus the run summary
 * the ledger records. A detector reports failure through run.status rather than
 * throwing, so a broken tool lands in the ledger instead of vanishing. The
 * broker decides what an "error" status means for the loop.
 */
export interface DetectorOutcome {
  run: DetectorRun;
  findings: Finding[];
}

/** What a whole detection layer pass produced, ready for the ledger. */
export interface DetectionResult {
  runs: DetectorRun[];
  findings: Finding[];
  /** Reported rather than swallowed, so a bad dedup is visible in the log. */
  duplicatesDropped: number;
}

export interface Scanner {
  readonly id: "semgrep" | "osv-scanner";
  scan(scope: DetectionScope): Promise<DetectorOutcome>;
}

export interface FuzzJob {
  harness: FuzzHarnessConfig;
  scope: DetectionScope;
  timeBudgetMs: number;
  /** Fixed so a run is reproducible; each internal restart derives from it. */
  seed: number;
}

export interface FuzzEngine {
  readonly id: FuzzEngineId;
  fuzz(job: FuzzJob): Promise<DetectorOutcome>;
}
