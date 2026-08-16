import type { z } from "zod";

import { formatIssues } from "../contracts/index.js";
import { BrokerError } from "./errors.js";

/**
 * Turns one agent turn's text into a contract, or stops the run.
 *
 * A turn is a stream of an agent thinking out loud and then answering, so the
 * answer is the last well formed JSON object in it, fenced or bare. Finding that
 * object is transport. Judging it is not: it has to satisfy the schema as it
 * stands, and an earlier object is never substituted for a final one that does
 * not, because the risk being avoided here is acting on a verdict the agent
 * revised rather than the one it settled on.
 */
export function parseAgentJson<S extends z.ZodType>(
  schema: S,
  text: string,
  subtask: string,
): z.infer<S> {
  const answer = jsonObjectsIn(text)
    .map((candidate) => tryParse(candidate))
    .filter((value) => value !== undefined)
    .at(-1);

  if (answer === undefined) {
    throw new BrokerError(
      `the ${subtask} turn answered with no readable JSON object: ${snippet(text)}`,
    );
  }

  const result = schema.safeParse(answer.value);
  if (!result.success) {
    throw new BrokerError(
      `the ${subtask} turn answered with output the schema rejected:\n${formatIssues(result.error.issues)}`,
      { cause: result.error },
    );
  }

  return result.data;
}

/**
 * Every balanced brace region in the text, in the order they appear. Strings and
 * their escapes are tracked so a brace inside a JSON string, or inside prose
 * quoting one, does not throw the depth off.
 */
function jsonObjectsIn(text: string): string[] {
  const objects: string[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
    } else if (char === "{") {
      if (depth === 0) {
        start = index;
      }
      depth += 1;
    } else if (char === "}" && depth > 0) {
      depth -= 1;
      if (depth === 0) {
        objects.push(text.slice(start, index + 1));
      }
    }
  }

  return objects;
}

function tryParse(candidate: string): { value: unknown } | undefined {
  try {
    return { value: JSON.parse(candidate) };
  } catch {
    // Prose that happened to balance a brace. The real answer is elsewhere in
    // the turn, and if it is not, the caller reports that nothing readable came.
    return undefined;
  }
}

function snippet(text: string): string {
  const flat = text.trim().replace(/\s+/g, " ");
  return flat.length <= 300 ? flat : `${flat.slice(0, 300)}...`;
}
