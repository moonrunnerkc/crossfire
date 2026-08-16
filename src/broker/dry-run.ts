import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { RunConfig } from "../config/index.js";
import type { Finding } from "../contracts/index.js";
import type { DetectionResult } from "../detection/index.js";
import { shellQuote } from "../detection/index.js";
import type { RefuzzOutcome } from "../gates/index.js";
import { BrokerError } from "./errors.js";
import type { AgentRunner, AgentTurn, DetectorRunner } from "./state-machine.js";

/**
 * The dry run exists to exercise the broker, the gates, git, and the ledger with
 * no scanners, no fuzzer, no compiler, and no models. Only the detectors and the
 * agents are stubbed; everything the broker decides mechanically it still decides
 * for real, which is what makes a dry run worth running at all.
 *
 * The one finding it carries hangs on a marker file outside the target: the
 * repro exits 0 while the marker is absent, and the stub fix creates it, so the
 * repro flips exactly the way a real fix flips one and nothing writes into the
 * repository under test.
 */
export function createDryRunDetectors(config: RunConfig, markerPath: string): DetectorRunner {
  const finding = dryRunFinding(config, markerPath);

  return {
    detect(round: number): Promise<DetectionResult> {
      return Promise.resolve({
        runs: [
          {
            detector: "semgrep",
            status: "ok",
            duration_ms: 0,
            findings_emitted: round === 1 ? 1 : 0,
            note: "dry run, no scanner was executed",
          },
        ],
        findings: round === 1 ? [finding] : [],
        duplicatesDropped: 0,
      });
    },

    refuzz(): Promise<RefuzzOutcome> {
      return Promise.resolve({
        runs: [
          {
            detector: "fuzz",
            status: "skipped",
            duration_ms: 0,
            findings_emitted: 0,
            note: "dry run, no fuzzer was executed",
          },
        ],
        newFindings: [],
      });
    },
  };
}

export function createDryRunAgents(markerPath: string): AgentRunner {
  return {
    run(turn: AgentTurn): Promise<string> {
      switch (turn.subtask) {
        case "cold-hunt":
          return Promise.resolve(JSON.stringify({ raises: [] }));

        case "candidate-confirmation":
          return Promise.resolve(
            JSON.stringify({
              status: "confirmed",
              finding_id: findingIdIn(turn),
              severity: "medium",
              repro_command: reproFor(markerPath),
              expected_secure_behavior: "the dry run marker exists",
            }),
          );

        case "fix-planning":
          return Promise.resolve(
            JSON.stringify({
              round: turn.round,
              summary: "One synthetic finding, closed by writing the dry run marker.",
            }),
          );

        case "fix": {
          mkdirSync(dirname(markerPath), { recursive: true });
          writeFileSync(markerPath, "closed by the dry run\n");
          return Promise.resolve(
            JSON.stringify({
              round: turn.round,
              agent: "claude",
              fixes: [
                {
                  finding_id: findingIdIn(turn),
                  files_changed: [DRY_RUN_FILE],
                  summary: "wrote the dry run marker, which is what its repro reads",
                },
              ],
            }),
          );
        }

        default:
          // A dry run that met a subtask it has no answer for would be pretending.
          return Promise.reject(
            new BrokerError(`the dry run has no answer for a ${turn.subtask} turn`),
          );
      }
    },
  };
}

const DRY_RUN_ID = "dry-run-finding";
const DRY_RUN_FILE = "the dry run touches no file";

function reproFor(markerPath: string): string {
  // Exit 0 while the marker is absent: the convention's "still present".
  return `test ! -f ${shellQuote(markerPath)}`;
}

function findingIdIn(turn: AgentTurn): string {
  if (!turn.prompt.includes(DRY_RUN_ID)) {
    throw new BrokerError(`a dry run turn arrived without its finding: ${turn.subtask}`);
  }
  return DRY_RUN_ID;
}

function dryRunFinding(config: RunConfig, markerPath: string): Finding {
  return {
    id: DRY_RUN_ID,
    source: "sast",
    confirmation_state: "candidate",
    severity: "medium",
    class: "dry-run",
    file: config.target.inScopeDirs[0] ?? "src",
    description: "a synthetic candidate, so a dry run exercises confirm, fix, and verify",
    repro_command: reproFor(markerPath),
    expected_secure_behavior: "the marker the dry run fix writes is present",
  };
}
