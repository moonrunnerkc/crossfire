import { z } from "zod";

import { SeveritySchema } from "../contracts/severity.js";

export const DEFAULT_EXCLUDED_PATHS = [
  ".env",
  ".env*",
  "**/.env*",
  "**/.npmrc",
  "**/.netrc",
  "**/.git-credentials",
  "**/.ssh/**",
  "**/.aws/**",
  "**/.gnupg/**",
  "**/secrets/**",
  "**/*credentials*",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",
  "**/*.keystore",
  "**/id_rsa*",
  "**/id_ed25519*",
] as const;

export const LOOP_DEFAULTS = {
  iterationCap: 5,
  severityBar: "medium",
  turnTimeoutMs: 300_000,
} as const;

export const FUZZ_ENGINES = ["libfuzzer", "afl++", "jazzer", "atheris"] as const;
export const FUZZ_LANGUAGES = ["c", "cpp", "java", "python"] as const;

export const FuzzEngineSchema = z.enum(FUZZ_ENGINES);
export const FuzzLanguageSchema = z.enum(FUZZ_LANGUAGES);

export type FuzzEngine = z.infer<typeof FuzzEngineSchema>;
export type FuzzLanguage = z.infer<typeof FuzzLanguageSchema>;

export const ENGINE_LANGUAGES: Record<FuzzEngine, readonly FuzzLanguage[]> = {
  libfuzzer: ["c", "cpp"],
  "afl++": ["c", "cpp"],
  jazzer: ["java"],
  atheris: ["python"],
};

const positiveMs = z.number().int().positive();
const path = z.string().min(1);

const FuzzHarnessSchema = z
  .strictObject({
    id: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/, "harness id must be a lowercase slug"),
    language: FuzzLanguageSchema,
    engine: FuzzEngineSchema,
    entryPoint: path,
    corpusDir: path,
  })
  .superRefine((harness, ctx) => {
    if (!ENGINE_LANGUAGES[harness.engine].includes(harness.language)) {
      ctx.addIssue({
        code: "custom",
        path: ["engine"],
        message: `fuzz engine ${harness.engine} does not support language ${harness.language}`,
      });
    }
  });

const FuzzConfigSchema = z
  .strictObject({
    enabled: z.boolean().default(true),
    timeBudgetMs: positiveMs,
    harnesses: z.array(FuzzHarnessSchema).superRefine((harnesses, ctx) => {
      const seen = new Set<string>();
      harnesses.forEach((harness, index) => {
        if (seen.has(harness.id)) {
          ctx.addIssue({
            code: "custom",
            path: [index, "id"],
            message: `duplicate harness id: ${harness.id}`,
          });
        }
        seen.add(harness.id);
      });
    }),
  })
  .superRefine((fuzz, ctx) => {
    if (fuzz.enabled && fuzz.harnesses.length === 0) {
      ctx.addIssue({
        code: "custom",
        path: ["harnesses"],
        message: "fuzzing is enabled but no harnesses are configured",
      });
    }
  });

const SemgrepConfigSchema = z.strictObject({
  enabled: z.boolean().default(true),
  ruleset: z.string().min(1),
  timeBudgetMs: positiveMs,
});

const OsvScannerConfigSchema = z.strictObject({
  enabled: z.boolean().default(true),
  lockfiles: z.array(path).min(1, "at least one lockfile is required"),
  timeBudgetMs: positiveMs,
});

const TargetSchema = z.strictObject({
  repoPath: path,
  inScopeDirs: z.array(path).min(1, "at least one in-scope directory is required"),
  excludedPaths: z
    .array(z.string().min(1))
    .default([])
    .transform((patterns) => [...new Set([...DEFAULT_EXCLUDED_PATHS, ...patterns])]),
  testCommand: z.string().min(1),
});

const LoopSchema = z
  .strictObject({
    iterationCap: z.number().int().positive().max(100).default(LOOP_DEFAULTS.iterationCap),
    severityBar: SeveritySchema.default(LOOP_DEFAULTS.severityBar),
    turnTimeoutMs: positiveMs.default(LOOP_DEFAULTS.turnTimeoutMs),
  })
  .default(() => ({ ...LOOP_DEFAULTS }));

export const RunConfigSchema = z.strictObject({
  task: z.string().min(1, "task must describe what this run is for"),
  target: TargetSchema,
  loop: LoopSchema,
  detectors: z.strictObject({
    semgrep: SemgrepConfigSchema,
    osvScanner: OsvScannerConfigSchema,
    fuzz: FuzzConfigSchema,
  }),
});

export type RunConfig = z.infer<typeof RunConfigSchema>;
export type FuzzHarnessConfig = RunConfig["detectors"]["fuzz"]["harnesses"][number];
