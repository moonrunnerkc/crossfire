import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { formatIssues } from "../contracts/issues.js";
import type { RunConfig } from "./schema.js";
import { RunConfigSchema } from "./schema.js";

export class ConfigError extends Error {
  constructor(message: string, options?: { cause: unknown }) {
    super(message, options);
    this.name = "ConfigError";
  }
}

export function parseRunConfig(value: unknown, sourceLabel: string, baseDir: string): RunConfig {
  const result = RunConfigSchema.safeParse(value);
  if (!result.success) {
    throw new ConfigError(`invalid config ${sourceLabel}:\n${formatIssues(result.error.issues)}`, {
      cause: result.error,
    });
  }
  const config = result.data;
  return {
    ...config,
    target: { ...config.target, repoPath: resolve(baseDir, config.target.repoPath) },
  };
}

export function loadRunConfig(configPath: string): RunConfig {
  const absolutePath = resolve(configPath);

  let source: string;
  try {
    source = readFileSync(absolutePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new ConfigError(`config file not found: ${absolutePath}`, { cause: error });
    }
    throw new ConfigError(`cannot read config file ${absolutePath}: ${(error as Error).message}`, {
      cause: error,
    });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new ConfigError(`invalid JSON in ${absolutePath}: ${(error as Error).message}`, {
      cause: error,
    });
  }

  return parseRunConfig(parsed, absolutePath, dirname(absolutePath));
}
