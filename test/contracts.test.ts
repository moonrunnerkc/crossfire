import { describe, expect, test } from "vitest";
import type { z } from "zod";

import {
  AgentEventSchema,
  FindingSchema,
  FindingsBatchSchema,
  FixReportSchema,
  meetsSeverityBar,
} from "../src/contracts/index.js";

function expectLosslessRoundTrip<T extends z.ZodType>(schema: T, value: unknown): void {
  const parsed = schema.parse(value);
  const reparsed = schema.parse(JSON.parse(JSON.stringify(parsed)));
  expect(reparsed).toEqual(parsed);
}

function fuzzerFinding(): Record<string, unknown> {
  return {
    id: "fuzz-parse-request-9f21",
    source: "fuzzer",
    confirmation_state: "confirmed",
    severity: "high",
    class: "heap-buffer-overflow",
    file: "src/parse_request.py",
    line: 42,
    description: "A request header longer than 64 bytes overruns the fixed header buffer.",
    repro_command: "./fuzz/replay.sh artifacts/crash-9f21",
    expected_secure_behavior: "Oversized headers are rejected without writing past the buffer.",
    crash_artifact: "artifacts/crash-9f21",
  };
}

function sastCandidate(): Record<string, unknown> {
  return {
    id: "semgrep-subprocess-shell-1",
    source: "sast",
    confirmation_state: "candidate",
    severity: "medium",
    class: "command-injection",
    file: "src/tasks.py",
    description: "subprocess call built from user input with shell=True.",
    repro_command: "python -m pytest fuzz/repro_command_injection.py",
    expected_secure_behavior: "User input never reaches a shell command string.",
  };
}

describe("FindingSchema", () => {
  test("parses a confirmed fuzzer finding carrying a crash artifact", () => {
    const finding = FindingSchema.parse(fuzzerFinding());

    expect(finding.source).toBe("fuzzer");
    expect(finding.confirmation_state).toBe("confirmed");
    expect(finding.crash_artifact).toBe("artifacts/crash-9f21");
  });

  test("rejects a fuzzer finding with no crash artifact", () => {
    const raw = fuzzerFinding();
    delete raw.crash_artifact;

    expect(() => FindingSchema.parse(raw)).toThrow(/crash_artifact/);
  });

  test("rejects a fuzzer finding whose crash artifact is empty", () => {
    const raw = { ...fuzzerFinding(), crash_artifact: "" };

    expect(() => FindingSchema.parse(raw)).toThrow(/crash_artifact/);
  });

  test("accepts a scanner candidate with no crash artifact", () => {
    const finding = FindingSchema.parse(sastCandidate());

    expect(finding.crash_artifact).toBeUndefined();
    expect(finding.line).toBeUndefined();
  });

  test("rejects an unknown source", () => {
    expect(() => FindingSchema.parse({ ...sastCandidate(), source: "vibes" })).toThrow(/source/);
  });

  test("rejects an unknown confirmation state", () => {
    expect(() =>
      FindingSchema.parse({ ...sastCandidate(), confirmation_state: "probably" }),
    ).toThrow(/confirmation_state/);
  });

  test("rejects an unknown severity", () => {
    expect(() => FindingSchema.parse({ ...sastCandidate(), severity: "spicy" })).toThrow(
      /severity/,
    );
  });

  test("rejects an empty repro command", () => {
    expect(() => FindingSchema.parse({ ...sastCandidate(), repro_command: "" })).toThrow(
      /repro_command/,
    );
  });

  test("rejects a missing expected secure behavior", () => {
    const raw = sastCandidate();
    delete raw.expected_secure_behavior;

    expect(() => FindingSchema.parse(raw)).toThrow(/expected_secure_behavior/);
  });

  test("rejects unknown keys instead of dropping them", () => {
    expect(() => FindingSchema.parse({ ...sastCandidate(), exploit: "rm -rf /" })).toThrow(
      /exploit/,
    );
  });

  test("rejects a non-positive line number", () => {
    expect(() => FindingSchema.parse({ ...sastCandidate(), line: 0 })).toThrow(/line/);
  });

  test("rejects an absolute file path", () => {
    expect(() => FindingSchema.parse({ ...sastCandidate(), file: "/etc/passwd" })).toThrow(/file/);
  });

  test("round-trips losslessly through JSON", () => {
    expectLosslessRoundTrip(FindingSchema, fuzzerFinding());
    expectLosslessRoundTrip(FindingSchema, sastCandidate());
  });
});

describe("FindingsBatchSchema", () => {
  test("parses a round of findings", () => {
    const batch = FindingsBatchSchema.parse({
      round: 1,
      findings: [fuzzerFinding(), sastCandidate()],
    });

    expect(batch.findings).toHaveLength(2);
  });

  test("accepts an empty findings array", () => {
    expect(FindingsBatchSchema.parse({ round: 3, findings: [] }).findings).toEqual([]);
  });

  test("rejects duplicate finding ids in one batch", () => {
    expect(() =>
      FindingsBatchSchema.parse({ round: 1, findings: [sastCandidate(), sastCandidate()] }),
    ).toThrow(/semgrep-subprocess-shell-1/);
  });

  test("rejects a round below one", () => {
    expect(() => FindingsBatchSchema.parse({ round: 0, findings: [] })).toThrow(/round/);
  });

  test("round-trips losslessly through JSON", () => {
    expectLosslessRoundTrip(FindingsBatchSchema, {
      round: 2,
      findings: [fuzzerFinding(), sastCandidate()],
    });
  });
});

describe("FixReportSchema", () => {
  const report = {
    round: 1,
    agent: "claude",
    fixes: [
      {
        finding_id: "fuzz-parse-request-9f21",
        files_changed: ["src/parse_request.py"],
        summary: "Bound the header copy to the destination buffer size.",
      },
    ],
  };

  test("parses a fix report", () => {
    expect(FixReportSchema.parse(report).fixes[0]?.finding_id).toBe("fuzz-parse-request-9f21");
  });

  test("rejects an unknown agent", () => {
    expect(() => FixReportSchema.parse({ ...report, agent: "gemini" })).toThrow(/agent/);
  });

  test("rejects a fix that changed no files", () => {
    const fixes = [{ ...report.fixes[0], files_changed: [] }];

    expect(() => FixReportSchema.parse({ ...report, fixes })).toThrow(/files_changed/);
  });

  test("rejects two fixes claiming the same finding", () => {
    const fixes = [report.fixes[0], report.fixes[0]];

    expect(() => FixReportSchema.parse({ ...report, fixes })).toThrow(/fuzz-parse-request-9f21/);
  });

  test("rejects unknown keys instead of dropping them", () => {
    expect(() => FixReportSchema.parse({ ...report, confidence: 0.9 })).toThrow(/confidence/);
  });

  test("round-trips losslessly through JSON", () => {
    expectLosslessRoundTrip(FixReportSchema, report);
  });
});

describe("AgentEventSchema", () => {
  const events = [
    { type: "text", text: "Patched the header copy." },
    { type: "thinking", text: "The overflow is in the memcpy on line 42." },
    { type: "tool_call", call_id: "call-1", name: "read_file", input: { path: "src/a.py" } },
    { type: "tool_result", call_id: "call-1", status: "ok", output: "def parse(): ..." },
    { type: "done", stop_reason: "end_turn" },
    { type: "error", message: "agent exited before completing the turn" },
  ];

  test("parses every normalized event variant", () => {
    for (const event of events) {
      expect(AgentEventSchema.parse(event).type).toBe(event.type);
    }
  });

  test("rejects an unknown event type", () => {
    expect(() => AgentEventSchema.parse({ type: "handoff", text: "over to you" })).toThrow(/type/);
  });

  test("rejects a tool call with no call id", () => {
    expect(() => AgentEventSchema.parse({ type: "tool_call", name: "read_file", input: {} })).toThrow(
      /call_id/,
    );
  });

  test("rejects a tool result with an unknown status", () => {
    expect(() =>
      AgentEventSchema.parse({ type: "tool_result", call_id: "call-1", status: "maybe", output: "" }),
    ).toThrow(/status/);
  });

  test("rejects an unknown stop reason", () => {
    expect(() => AgentEventSchema.parse({ type: "done", stop_reason: "vibes" })).toThrow(
      /stop_reason/,
    );
  });

  test("rejects a non-serializable tool call input", () => {
    expect(() =>
      AgentEventSchema.parse({ type: "tool_call", call_id: "c", name: "x", input: () => 1 }),
    ).toThrow(/input/);
  });

  test("round-trips every variant losslessly through JSON", () => {
    for (const event of events) {
      expectLosslessRoundTrip(AgentEventSchema, event);
    }
  });
});

describe("meetsSeverityBar", () => {
  test("accepts severities at or above the bar", () => {
    expect(meetsSeverityBar("critical", "medium")).toBe(true);
    expect(meetsSeverityBar("medium", "medium")).toBe(true);
  });

  test("rejects severities below the bar", () => {
    expect(meetsSeverityBar("low", "medium")).toBe(false);
    expect(meetsSeverityBar("info", "low")).toBe(false);
  });
});
