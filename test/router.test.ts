import { describe, expect, test } from "vitest";

import { AGENT_IDS } from "../src/contracts/index.js";
import type { SubtaskClass } from "../src/router/index.js";
import { ROUTING_TABLE, RoutingError, SUBTASK_CLASSES, routeSubtask } from "../src/router/index.js";

/** Anything a deterministic detector does. None of it is an agent's to decide. */
const DETECTION_WORDS = ["detect", "scan", "fuzz", "sast", "sca", "triage"];

describe("capability routing", () => {
  test("the reasoning classes go to Grok", () => {
    expect(routeSubtask("crash-analysis")).toBe("grok");
    expect(routeSubtask("candidate-confirmation")).toBe("grok");
    expect(routeSubtask("repro-authoring")).toBe("grok");
    expect(routeSubtask("exploitability-assessment")).toBe("grok");
  });

  test("the code writing classes go to Claude", () => {
    expect(routeSubtask("fix")).toBe("claude");
    expect(routeSubtask("refactor")).toBe("claude");
    expect(routeSubtask("test-repair")).toBe("claude");
  });

  test("every declared class has a route", () => {
    for (const subtask of SUBTASK_CLASSES) {
      expect(AGENT_IDS).toContain(routeSubtask(subtask));
    }
    expect(Object.keys(ROUTING_TABLE).sort()).toEqual([...SUBTASK_CLASSES].sort());
  });

  test("the table holds nothing else", () => {
    // A class added to the table without a test here would slip through the
    // coverage above, which iterates the table rather than the expectation.
    expect(SUBTASK_CLASSES).toHaveLength(7);
  });

  test("detection is not a routable class", () => {
    for (const subtask of SUBTASK_CLASSES) {
      for (const word of DETECTION_WORDS) {
        expect(subtask).not.toContain(word);
      }
    }

    for (const notAnAgentClass of ["detection", "scanning", "fuzzing", "crash-detection"]) {
      expect(() => routeSubtask(notAnAgentClass as SubtaskClass)).toThrow(RoutingError);
    }
  });

  test("an unknown class is rejected rather than defaulted", () => {
    expect(() => routeSubtask("summarize" as SubtaskClass)).toThrow(/unknown subtask class/);
    expect(() => routeSubtask("" as SubtaskClass)).toThrow(RoutingError);
  });

  test("a class borrowed from Object.prototype is not a route", () => {
    expect(() => routeSubtask("toString" as SubtaskClass)).toThrow(RoutingError);
    expect(() => routeSubtask("constructor" as SubtaskClass)).toThrow(RoutingError);
  });
});
