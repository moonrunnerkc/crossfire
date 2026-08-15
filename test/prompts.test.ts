import { resolve } from "node:path";
import { describe, expect, test } from "vitest";

import type { RunConfig } from "../src/config/index.js";
import { loadRunConfig } from "../src/config/index.js";
import type { Finding, FindingsBatch } from "../src/contracts/index.js";
import {
  buildCandidateConfirmationPrompt,
  buildCrashAnalysisPrompt,
  buildFixPrompt,
} from "../src/broker/index.js";

const SAMPLE_CONFIG = resolve(import.meta.dirname, "..", "crossfire.sample.json");

function config(): RunConfig {
  return loadRunConfig(SAMPLE_CONFIG);
}

const CRASH: Finding = {
  id: "fuzz-4b21c9de7a10",
  source: "fuzzer",
  confirmation_state: "confirmed",
  severity: "high",
  class: "heap-buffer-overflow",
  file: "src/parse_request.c",
  line: 32,
  description:
    "heap-buffer-overflow reproduced by the parse-request harness. Crash stack: parse_request (parse_request.c:32) <- LLVMFuzzerTestOneInput (parse_request_harness.c:19).",
  repro_command:
    "! './build/parse-request-fuzzer' -timeout=25 '.crossfire/crashes/parse-request/fuzz-4b21c9de7a10.min'",
  expected_secure_behavior:
    "the parse-request harness returns normally for the recorded input instead of aborting with heap-buffer-overflow.",
  crash_artifact: ".crossfire/crashes/parse-request/fuzz-4b21c9de7a10.min",
};

const CANDIDATE: Finding = {
  id: "sast-90ab12cd34ef",
  source: "sast",
  confirmation_state: "candidate",
  severity: "medium",
  class: "insecure-strcpy",
  file: "src/parse_request.c",
  line: 28,
  description: "strcpy writes an unbounded request path into a 32 byte buffer",
  repro_command: "false",
  expected_secure_behavior: "the copy is bounded by the size of the destination buffer",
};

const BATCH: FindingsBatch = { round: 2, findings: [CRASH, { ...CANDIDATE, confirmation_state: "confirmed" }] };

const DIFF = `diff --git a/src/parse_request.c b/src/parse_request.c
index 1111111..2222222 100644
--- a/src/parse_request.c
+++ b/src/parse_request.c
@@ -20,7 +20,7 @@ int parse_request(const char *line, struct request *out) {
-  strcpy(out->path, path);
+  memcpy(out->path, path, path_len + 1);
`;

describe("crash analysis prompt", () => {
  test("renders a stable prompt from one confirmed crash", () => {
    expect(buildCrashAnalysisPrompt({ config: config(), finding: CRASH })).toMatchSnapshot();
  });

  test("carries the artifact, the detector repro, and the exit code convention", () => {
    const prompt = buildCrashAnalysisPrompt({ config: config(), finding: CRASH });

    expect(prompt).toContain(CRASH.crash_artifact!);
    expect(prompt).toContain(CRASH.repro_command);
    expect(prompt).toContain("exit 0 means the bug is still present");
  });

  test("renders the same text twice for the same finding", () => {
    const once = buildCrashAnalysisPrompt({ config: config(), finding: CRASH });
    const twice = buildCrashAnalysisPrompt({ config: config(), finding: CRASH });

    expect(once).toBe(twice);
  });

  test("a different crash renders a different prompt", () => {
    const other = buildCrashAnalysisPrompt({
      config: config(),
      finding: { ...CRASH, id: "fuzz-ffffffffffff", class: "heap-use-after-free" },
    });

    expect(other).not.toBe(buildCrashAnalysisPrompt({ config: config(), finding: CRASH }));
  });
});

describe("candidate confirmation prompt", () => {
  test("renders a stable prompt from one scanner candidate", () => {
    expect(
      buildCandidateConfirmationPrompt({ config: config(), finding: CANDIDATE }),
    ).toMatchSnapshot();
  });

  test("says the broker runs the repro before the candidate can be fixed", () => {
    const prompt = buildCandidateConfirmationPrompt({ config: config(), finding: CANDIDATE });

    expect(prompt).toContain("dismissed");
    expect(prompt).toContain("The broker runs your repro command itself");
  });

  test("offers exactly the two verdicts and asks for neither a plan nor a next step", () => {
    const prompt = buildCandidateConfirmationPrompt({ config: config(), finding: CANDIDATE });

    expect(prompt).toContain(`"status": "confirmed"`);
    expect(prompt).toContain(`"status": "dismissed"`);
    expect(prompt.toLowerCase()).not.toContain("what should");
    expect(prompt.toLowerCase()).not.toContain("next step");
  });
});

describe("fix prompt", () => {
  test("renders a stable prompt from a confirmed batch", () => {
    expect(buildFixPrompt({ config: config(), batch: BATCH })).toMatchSnapshot();
  });

  test("renders a stable prompt when a round has a diff to carry", () => {
    expect(buildFixPrompt({ config: config(), batch: BATCH, diff: DIFF })).toMatchSnapshot();
  });

  test("lists every finding with the repro that has to be made to fail", () => {
    const prompt = buildFixPrompt({ config: config(), batch: BATCH });

    for (const finding of BATCH.findings) {
      expect(prompt).toContain(finding.id);
      expect(prompt).toContain(finding.repro_command);
    }
    expect(prompt).toContain("must exit non-zero after your change");
  });

  test("states the out of scope rule and the in scope directories", () => {
    const prompt = buildFixPrompt({ config: config(), batch: BATCH });

    expect(prompt).toContain("src");
    expect(prompt).toContain("Change only files under the in scope directories");
    expect(prompt).toContain("Do not weaken or delete a repro, a test, or a harness");
  });

  test("omits the diff section entirely when there is nothing changed yet", () => {
    expect(buildFixPrompt({ config: config(), batch: BATCH })).not.toContain("git diff");
  });
});

describe("every template", () => {
  const prompts = (): string[] => [
    buildCrashAnalysisPrompt({ config: config(), finding: CRASH }),
    buildCandidateConfirmationPrompt({ config: config(), finding: CANDIDATE }),
    buildFixPrompt({ config: config(), batch: BATCH, diff: DIFF }),
  ];

  test("keeps the absolute target path out of the agent's context", () => {
    // Machine specific paths would also make these snapshots unstable.
    for (const prompt of prompts()) {
      expect(prompt).not.toContain(config().target.repoPath);
    }
  });

  test("asks for one JSON object and nothing else", () => {
    for (const prompt of prompts()) {
      expect(prompt).toContain("Answer with one JSON object and nothing else");
    }
  });
});
