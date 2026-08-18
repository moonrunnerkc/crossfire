import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { z } from "zod";

import type { RunConfig } from "../config/index.js";
import type { Finding, Severity } from "../contracts/index.js";
import { runTool, shellQuote } from "./exec.js";
import { sastFindingId, toSlug } from "./identity.js";
import { partitionByScope } from "./scope.js";
import type { DetectionScope, DetectorOutcome, Scanner } from "./types.js";

type SemgrepConfig = RunConfig["detectors"]["semgrep"];

/** Byte offsets into the file, which is how the flagged construct is read back. */
const byteOffset = z.number().int().nonnegative().optional();

const SemgrepResultSchema = z.object({
  check_id: z.string().min(1),
  path: z.string().min(1),
  start: z.object({ line: z.number().int().nonnegative(), offset: byteOffset }),
  end: z.object({ offset: byteOffset }).optional(),
  extra: z.object({
    message: z.string().optional(),
    severity: z.string().optional(),
    metadata: z
      .object({ cwe: z.union([z.string(), z.array(z.string())]).optional() })
      .optional(),
  }),
});

const SemgrepOutputSchema = z.object({
  results: z.array(SemgrepResultSchema),
  errors: z.array(z.object({ message: z.string().optional() })).optional(),
});

type SemgrepResult = z.infer<typeof SemgrepResultSchema>;

const SEVERITY_BY_SEMGREP: Record<string, Severity> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
};

function severityOf(result: SemgrepResult): Severity {
  return SEVERITY_BY_SEMGREP[result.extra.severity ?? ""] ?? "medium";
}

/**
 * The bug category, preferring the rule's CWE ("CWE-787: Out-of-bounds Write"
 * becomes out-of-bounds-write) so the class survives a rule being renamed and
 * lines up with what a fuzzer crash class looks like. Rules with no CWE fall
 * back to the last segment of the check id.
 */
function classOf(result: SemgrepResult): string {
  const cwe = result.extra.metadata?.cwe;
  const first = Array.isArray(cwe) ? cwe[0] : cwe;
  if (first !== undefined && first.trim().length > 0) {
    const named = /^CWE-\d+:\s*(.+)$/i.exec(first.trim());
    return toSlug(named?.[1] ?? first);
  }
  return toSlug(result.check_id.split(".").at(-1) ?? result.check_id);
}

/**
 * A candidate's repro asks the scanner the same question again, narrowed to the
 * one file: exit 0 while the rule still fires there. Grok replaces this with a
 * dynamic proof when it promotes the candidate to confirmed.
 */
function reproCommand(config: SemgrepConfig, result: SemgrepResult): string {
  const scan = [
    "semgrep",
    "scan",
    "--config",
    shellQuote(config.ruleset),
    "--json",
    "--quiet",
    "--metrics=off",
    shellQuote(result.path),
  ].join(" ");
  return `${scan} | grep -q ${shellQuote(result.check_id)}`;
}

export function normalizeSemgrepOutput(
  output: z.infer<typeof SemgrepOutputSchema>,
  config: SemgrepConfig,
  repoPath: string,
): Finding[] {
  const sources = new Map<string, string>();
  return outermostMatches(output.results).map((result) =>
    toFinding(config, result, flaggedSource(result, repoPath, sources)),
  );
}

/**
 * One construct, one finding. A rule that matches a chained expression reports it once per
 * link, each match spanning one more call than the last, and every one of those is a
 * different flagged source and so a different id: five lines of `escapeHtml` arrived as four
 * findings, and at a lower severity bar that is four confirmation turns spent arguing about
 * the same function.
 *
 * The same principle the ids already rest on, applied one level up. An id answers "is this
 * the same finding as before"; this answers "is this the same finding as the one beside it",
 * and a match wholly inside another match of the same rule in the same file is the inner
 * spelling of the outer one. The outermost is kept because it is the construct a fix has to
 * change, and a match with no offsets to compare is kept as itself rather than guessed at.
 */
function outermostMatches(results: readonly SemgrepResult[]): readonly SemgrepResult[] {
  const contains = (outer: SemgrepResult, inner: SemgrepResult): boolean => {
    const outerStart = outer.start.offset;
    const outerEnd = outer.end?.offset;
    const innerStart = inner.start.offset;
    const innerEnd = inner.end?.offset;
    if (
      outerStart === undefined ||
      outerEnd === undefined ||
      innerStart === undefined ||
      innerEnd === undefined
    ) {
      return false;
    }
    const sameSpan = outerStart === innerStart && outerEnd === innerEnd;
    return !sameSpan && outerStart <= innerStart && innerEnd <= outerEnd;
  };

  return results.filter(
    (candidate) =>
      !results.some(
        (other) =>
          other.check_id === candidate.check_id &&
          other.path === candidate.path &&
          contains(other, candidate),
      ),
  );
}

/**
 * The source the rule matched, read back out of the file by byte offset. Semgrep
 * reports the matched text itself only when the CLI is logged in, so `extra.lines`
 * comes back as "requires login" and cannot be used. An empty string here means
 * the id identifies the finding by rule and file alone.
 */
function flaggedSource(
  result: SemgrepResult,
  repoPath: string,
  sources: Map<string, string>,
): string {
  const start = result.start.offset;
  const end = result.end?.offset;
  if (start === undefined || end === undefined || end <= start) {
    return "";
  }

  let source = sources.get(result.path);
  if (source === undefined) {
    try {
      source = readFileSync(resolve(repoPath, result.path), "utf8");
    } catch {
      // A path semgrep reported but we cannot open. The finding still stands, it
      // just identifies itself more coarsely.
      source = "";
    }
    sources.set(result.path, source);
  }
  return source.slice(start, end);
}

function toFinding(config: SemgrepConfig, result: SemgrepResult, flagged: string): Finding {
  const bugClass = classOf(result);
  const line = result.start.line > 0 ? result.start.line : undefined;
  const message = (result.extra.message ?? "").trim();

  return {
    id: sastFindingId(result.check_id, result.path, flagged),
    source: "sast",
    confirmation_state: "candidate",
    severity: severityOf(result),
    class: bugClass,
    file: result.path,
    ...(line === undefined ? {} : { line }),
    description:
      message.length > 0
        ? `${message} (semgrep rule ${result.check_id})`
        : `semgrep rule ${result.check_id} matched here`,
    repro_command: reproCommand(config, result),
    expected_secure_behavior: `${result.path} no longer matches semgrep rule ${result.check_id}, because the flagged construct is replaced by a bounded, validated equivalent.`,
  };
}

export function createSemgrepScanner(config: SemgrepConfig): Scanner {
  return {
    id: "semgrep",

    async scan(scope: DetectionScope): Promise<DetectorOutcome> {
      // Two layers: excluded directories never reach the command line, and
      // --exclude keeps semgrep out of anything excluded further down the tree.
      const targets = partitionByScope(scope, scope.inScopeDirs);
      if (targets.allowed.length === 0) {
        return {
          run: {
            detector: "semgrep",
            status: "skipped",
            duration_ms: 0,
            findings_emitted: 0,
            note: "every in-scope directory is excluded",
          },
          findings: [],
        };
      }

      const args = [
        "scan",
        "--config",
        config.ruleset,
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        ...scope.excludedPaths.flatMap((pattern) => ["--exclude", pattern]),
        ...targets.allowed,
      ];

      const result = await runTool("semgrep", args, {
        cwd: scope.repoPath,
        timeoutMs: config.timeBudgetMs,
      });

      const notes =
        targets.denied.length === 0
          ? []
          : [`skipped excluded directories: ${targets.denied.join(", ")}`];
      const base = { detector: "semgrep", duration_ms: result.durationMs } as const;

      if (result.spawnError !== undefined) {
        return {
          run: { ...base, status: "error", findings_emitted: 0, note: result.spawnError },
          findings: [],
        };
      }
      if (result.timedOut) {
        return {
          run: {
            ...base,
            status: "timeout",
            findings_emitted: 0,
            note: `semgrep exceeded its ${config.timeBudgetMs}ms budget`,
          },
          findings: [],
        };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(result.stdout);
      } catch {
        return {
          run: {
            ...base,
            status: "error",
            findings_emitted: 0,
            note: `semgrep exit ${result.exitCode} produced no JSON: ${result.stderr.trim().slice(0, 300)}`,
          },
          findings: [],
        };
      }

      const output = SemgrepOutputSchema.safeParse(parsed);
      if (!output.success) {
        return {
          run: {
            ...base,
            status: "error",
            findings_emitted: 0,
            note: `semgrep JSON did not match the expected shape: ${output.error.issues[0]?.message ?? "unknown"}`,
          },
          findings: [],
        };
      }

      const findings = normalizeSemgrepOutput(output.data, config, scope.repoPath);
      const scanErrors = output.data.errors ?? [];
      if (scanErrors.length > 0) {
        notes.push(
          `semgrep reported ${scanErrors.length} scan error(s): ${scanErrors[0]?.message ?? ""}`,
        );
      }

      return {
        run: {
          ...base,
          status: "ok",
          findings_emitted: findings.length,
          ...(notes.length > 0 ? { note: notes.join("; ") } : {}),
        },
        findings,
      };
    },
  };
}
