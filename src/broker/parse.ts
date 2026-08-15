import type { z } from "zod";

import { formatIssues } from "../contracts/index.js";
import { BrokerError } from "./errors.js";

/**
 * Agents wrap JSON in a fenced block often enough that unwrapping one is
 * transport, not leniency. Nothing else about the answer is forgiven.
 */
const FENCED = /^\s*```(?:json)?\s*([\s\S]*?)\s*```\s*$/;

/**
 * Turns one agent turn's text into a contract, or stops the run. There is no
 * middle path: output that misses the schema is not repaired, retried, or
 * partially used, because a fix round built on a half-understood answer is worse
 * than a round that did not happen.
 */
export function parseAgentJson<S extends z.ZodType>(
  schema: S,
  text: string,
  subtask: string,
): z.infer<S> {
  const source = FENCED.exec(text)?.[1] ?? text;

  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw new BrokerError(
      `the ${subtask} turn did not answer with JSON: ${(error as Error).message}`,
      { cause: error },
    );
  }

  const result = schema.safeParse(value);
  if (!result.success) {
    throw new BrokerError(
      `the ${subtask} turn answered with output the schema rejected:\n${formatIssues(result.error.issues)}`,
      { cause: result.error },
    );
  }

  return result.data;
}
