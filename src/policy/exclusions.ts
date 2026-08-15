import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import picomatch from "picomatch";

export interface PathDecision {
  allowed: boolean;
  reason: string;
  /** Repo relative posix path, present only when the path landed inside the repo. */
  relativePath?: string;
}

export interface PathScope {
  readonly repoPath: string;
  /** Decides whether a path may be touched at all, by anyone. */
  check(path: string): PathDecision;
  /** Whether a repo relative path is covered by the exclusion set. */
  isExcluded(relativePath: string): boolean;
}

export class PolicyError extends Error {
  constructor(message: string, options?: { cause: unknown }) {
    super(message, options);
    this.name = "PolicyError";
  }
}

/**
 * Resolves symlinks as far as the path actually exists, then re-attaches the
 * part that does not. A write target need not exist yet, but the directory it
 * lands in does, and that is what a symlink escape would have to go through.
 */
function realPathOfNearestExisting(absolute: string): string {
  const tail: string[] = [];
  let current = absolute;

  for (;;) {
    if (existsSync(current)) {
      return join(realpathSync(current), ...tail.reverse());
    }
    const parent = dirname(current);
    if (parent === current) {
      return absolute;
    }
    tail.push(basename(current));
    current = parent;
  }
}

function toPosix(path: string): string {
  return path.split(sep).join("/");
}

/**
 * The single gate every path crosses: agents through the ACP filesystem and
 * permission handlers, detectors through their own scope checks. A path is
 * usable only when it resolves inside the target repo and matches no exclusion
 * pattern. Symlinks are resolved first, so a link pointing at /etc or at .env
 * is denied on where it lands rather than on how it is spelled.
 */
export function createPathScope(repoPath: string, excludedPaths: readonly string[]): PathScope {
  if (!existsSync(repoPath)) {
    throw new PolicyError(`target repo does not exist: ${repoPath}`);
  }
  const root = realpathSync(resolve(repoPath));
  const matches = picomatch([...excludedPaths], { dot: true });

  function isExcluded(relativePath: string): boolean {
    const segments = relativePath.split("/").filter((segment) => segment.length > 0);
    // Every ancestor is tested too, so excluding a directory excludes what is
    // under it even when the pattern does not spell out a trailing glob.
    for (let depth = 1; depth <= segments.length; depth += 1) {
      if (matches(segments.slice(0, depth).join("/"))) {
        return true;
      }
    }
    return false;
  }

  return {
    repoPath: root,
    isExcluded,

    check(path: string): PathDecision {
      if (path.trim().length === 0) {
        return { allowed: false, reason: "empty path" };
      }

      const absolute = isAbsolute(path) ? path : resolve(root, path);
      const real = realPathOfNearestExisting(absolute);
      const rel = relative(root, real);

      if (rel.startsWith("..") || isAbsolute(rel)) {
        return { allowed: false, reason: `${path} resolves outside the target repo` };
      }

      const relativePath = toPosix(rel);
      if (isExcluded(relativePath)) {
        return {
          allowed: false,
          reason: `${relativePath} is an excluded path`,
          relativePath,
        };
      }

      return { allowed: true, reason: "in scope", relativePath };
    },
  };
}
