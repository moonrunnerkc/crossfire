import type { RunConfig } from "../config/index.js";
import { createPathScope } from "../policy/index.js";
import type { DetectionScope } from "./types.js";

export function scopeOf(config: RunConfig): DetectionScope {
  // Detectors are kept out of both lists. Only excludedPaths reaches the permission policy,
  // so a path excluded from scanning alone stays writable by the fix agent.
  const detectorExclusions = [...config.target.excludedPaths, ...config.target.scanExcludes];
  return {
    repoPath: config.target.repoPath,
    inScopeDirs: config.target.inScopeDirs,
    excludedPaths: detectorExclusions,
    pathScope: createPathScope(config.target.repoPath, detectorExclusions),
  };
}

/**
 * Splits configured paths into the ones a detector may open and the ones the
 * exclusion set keeps it out of. Denied paths come back rather than being
 * quietly dropped, so a detector run can say what it did not look at.
 */
export function partitionByScope(
  scope: DetectionScope,
  paths: readonly string[],
): { allowed: string[]; denied: string[] } {
  const allowed: string[] = [];
  const denied: string[] = [];

  for (const path of paths) {
    if (scope.pathScope.check(path).allowed) {
      allowed.push(path);
    } else {
      denied.push(path);
    }
  }

  return { allowed, denied };
}
