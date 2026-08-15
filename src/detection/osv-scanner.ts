import { isAbsolute, relative } from "node:path";

import { z } from "zod";

import type { RunConfig } from "../config/index.js";
import type { Finding, Severity } from "../contracts/index.js";
import { runTool, shellQuote } from "./exec.js";
import { scaFindingId } from "./identity.js";
import { partitionByScope } from "./scope.js";
import type { DetectionScope, DetectorOutcome, Scanner } from "./types.js";

type OsvConfig = RunConfig["detectors"]["osvScanner"];

const OsvOutputSchema = z.object({
  results: z.array(
    z.object({
      source: z.object({ path: z.string().min(1) }),
      packages: z.array(
        z.object({
          package: z.object({
            name: z.string().min(1),
            version: z.string().min(1),
            ecosystem: z.string().min(1),
          }),
          vulnerabilities: z
            .array(z.object({ id: z.string().min(1), summary: z.string().optional() }))
            .optional(),
          groups: z
            .array(
              z.object({
                ids: z.array(z.string().min(1)).min(1),
                aliases: z.array(z.string()).optional(),
                max_severity: z.string().optional(),
              }),
            )
            .optional(),
        }),
      ),
    }),
  ),
});

/**
 * OSV reports CVSS base scores. The bands are the standard CVSS v3 qualitative
 * ratings. An advisory with no score still names a real vulnerable dependency,
 * so it floors at medium rather than disappearing under the severity bar.
 */
function severityOf(maxSeverity: string | undefined): Severity {
  const score = Number.parseFloat(maxSeverity ?? "");
  if (!Number.isFinite(score)) {
    return "medium";
  }
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

function repoRelative(path: string, repoPath: string): string {
  const candidate = isAbsolute(path) ? relative(repoPath, path) : path;
  return candidate.split("\\").join("/");
}

function reproCommand(lockfile: string, advisoryId: string): string {
  const scan = [
    "osv-scanner",
    "scan",
    "source",
    `--lockfile=${shellQuote(lockfile)}`,
    "--format=json",
  ].join(" ");
  return `${scan} | grep -q ${shellQuote(advisoryId)}`;
}

export function createOsvScanner(config: OsvConfig): Scanner {
  return {
    id: "osv-scanner",

    async scan(scope: DetectionScope): Promise<DetectorOutcome> {
      const lockfiles = partitionByScope(scope, config.lockfiles);
      if (lockfiles.allowed.length === 0) {
        return {
          run: {
            detector: "osv-scanner",
            status: "skipped",
            duration_ms: 0,
            findings_emitted: 0,
            note: "every configured lockfile is outside the scope or excluded",
          },
          findings: [],
        };
      }

      const args = [
        "scan",
        "source",
        ...lockfiles.allowed.map((lockfile) => `--lockfile=${lockfile}`),
        "--format=json",
      ];

      const result = await runTool("osv-scanner", args, {
        cwd: scope.repoPath,
        timeoutMs: config.timeBudgetMs,
      });

      const base = { detector: "osv-scanner", duration_ms: result.durationMs } as const;

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
            note: `osv-scanner exceeded its ${config.timeBudgetMs}ms budget`,
          },
          findings: [],
        };
      }

      // osv-scanner exits 1 when it finds vulnerabilities, so the JSON on stdout
      // decides whether the run worked, not the exit code.
      let parsed: unknown;
      try {
        parsed = JSON.parse(result.stdout);
      } catch {
        return {
          run: {
            ...base,
            status: "error",
            findings_emitted: 0,
            note: `osv-scanner exit ${result.exitCode} produced no JSON: ${result.stderr.trim().slice(0, 300)}`,
          },
          findings: [],
        };
      }

      const output = OsvOutputSchema.safeParse(parsed);
      if (!output.success) {
        return {
          run: {
            ...base,
            status: "error",
            findings_emitted: 0,
            note: `osv-scanner JSON did not match the expected shape: ${output.error.issues[0]?.message ?? "unknown"}`,
          },
          findings: [],
        };
      }

      const findings = normalizeOsvOutput(output.data, scope.repoPath);
      return {
        run: {
          ...base,
          status: "ok",
          findings_emitted: findings.length,
          ...(lockfiles.denied.length > 0
            ? { note: `skipped excluded lockfiles: ${lockfiles.denied.join(", ")}` }
            : {}),
        },
        findings,
      };
    },
  };
}

/**
 * One finding per advisory group. osv-scanner already groups aliased records
 * (a GHSA and its CVE), so grouping is where the deduplicated advisory lives.
 */
export function normalizeOsvOutput(
  output: z.infer<typeof OsvOutputSchema>,
  repoPath: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const result of output.results) {
    const lockfile = repoRelative(result.source.path, repoPath);

    for (const entry of result.packages) {
      const { name, version, ecosystem } = entry.package;
      const summaries = new Map(
        (entry.vulnerabilities ?? []).map((vuln) => [vuln.id, vuln.summary ?? ""]),
      );

      for (const group of entry.groups ?? []) {
        const advisoryId = group.ids[0]!;
        const aliases = (group.aliases ?? []).filter((alias) => alias !== advisoryId);
        const summary = summaries.get(advisoryId) ?? "";

        findings.push({
          id: scaFindingId(ecosystem, name, version, advisoryId),
          source: "sca",
          confirmation_state: "candidate",
          severity: severityOf(group.max_severity),
          class: "vulnerable-dependency",
          file: lockfile,
          description: [
            `${advisoryId}${aliases.length > 0 ? ` (${aliases.join(", ")})` : ""}`,
            `affects ${ecosystem} package ${name}@${version} pinned in ${lockfile}.`,
            summary,
          ]
            .join(" ")
            .trim(),
          repro_command: reproCommand(lockfile, advisoryId),
          expected_secure_behavior: `${lockfile} pins ${name} to a version outside the range affected by ${advisoryId}, so osv-scanner no longer reports it.`,
        });
      }
    }
  }

  return findings;
}
