import type { RunConfig } from "../config/index.js";
import type { DetectorRun, Finding } from "../contracts/index.js";
import { dedupeFindings } from "./identity.js";
import { createOsvScanner } from "./osv-scanner.js";
import { scopeOf } from "./scope.js";
import { createSemgrepScanner } from "./semgrep.js";
import type { DetectionResult, Scanner } from "./types.js";

function skipped(detector: DetectorRun["detector"]): DetectorRun {
  return {
    detector,
    status: "skipped",
    duration_ms: 0,
    findings_emitted: 0,
    note: "disabled in the run config",
  };
}

/**
 * Runs every enabled scanner against the configured scope and collapses their
 * candidates into one deduplicated set. Scanners run in a fixed order so a
 * round's findings hash does not depend on process scheduling.
 */
export async function runScanners(config: RunConfig): Promise<DetectionResult> {
  const scope = scopeOf(config);
  const runs: DetectorRun[] = [];
  const collected: Finding[] = [];

  const scanners: [enabled: boolean, detector: DetectorRun["detector"], build: () => Scanner][] = [
    [
      config.detectors.semgrep.enabled,
      "semgrep",
      () => createSemgrepScanner(config.detectors.semgrep),
    ],
    [
      config.detectors.osvScanner.enabled,
      "osv-scanner",
      () => createOsvScanner(config.detectors.osvScanner),
    ],
  ];

  for (const [enabled, detector, build] of scanners) {
    if (!enabled) {
      runs.push(skipped(detector));
      continue;
    }
    const outcome = await build().scan(scope);
    runs.push(outcome.run);
    collected.push(...outcome.findings);
  }

  const { findings, duplicatesDropped } = dedupeFindings(collected);
  return { runs, findings, duplicatesDropped };
}
