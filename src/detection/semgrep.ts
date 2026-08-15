import { z } from "zod";

import type { RunConfig } from "../config/index.js";
import type { Finding, Severity } from "../contracts/index.js";
import { runTool, shellQuote } from "./exec.js";
import { sastFindingId, toSlug } from "./identity.js";
import type { DetectionScope, DetectorOutcome, Scanner } from "./types.js";

type SemgrepConfig = RunConfig["detectors"]["semgrep"];

const SemgrepResultSchema = z.object({
  check_id: z.string().min(1),
  path: z.string().min(1),
  start: z.object({ line: z.number().int().nonnegative() }),
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
): Finding[] {
  return output.results.map((result) => toFinding(config, result));
}

function toFinding(config: SemgrepConfig, result: SemgrepResult): Finding {
  const bugClass = classOf(result);
  const line = result.start.line > 0 ? result.start.line : undefined;
  const message = (result.extra.message ?? "").trim();

  return {
    id: sastFindingId(bugClass, result.path, line),
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
      const args = [
        "scan",
        "--config",
        config.ruleset,
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        ...scope.excludedPaths.flatMap((pattern) => ["--exclude", pattern]),
        ...scope.inScopeDirs,
      ];

      const result = await runTool("semgrep", args, {
        cwd: scope.repoPath,
        timeoutMs: config.timeBudgetMs,
      });

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

      const findings = normalizeSemgrepOutput(output.data, config);
      const scanErrors = output.data.errors ?? [];
      return {
        run: {
          ...base,
          status: "ok",
          findings_emitted: findings.length,
          ...(scanErrors.length > 0
            ? { note: `semgrep reported ${scanErrors.length} scan error(s): ${scanErrors[0]?.message ?? ""}` }
            : {}),
        },
        findings,
      };
    },
  };
}
