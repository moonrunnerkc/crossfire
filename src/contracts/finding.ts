import { z } from "zod";

import { SeveritySchema } from "./severity.js";

export const FINDING_SOURCES = ["fuzzer", "sast", "sca", "secret"] as const;
export const CONFIRMATION_STATES = ["confirmed", "candidate", "dismissed"] as const;

export const FindingSourceSchema = z.enum(FINDING_SOURCES);
export const ConfirmationStateSchema = z.enum(CONFIRMATION_STATES);

export type FindingSource = z.infer<typeof FindingSourceSchema>;
export type ConfirmationState = z.infer<typeof ConfirmationStateSchema>;

const repoRelativePath = z
  .string()
  .min(1)
  .refine(
    (value) => !value.startsWith("/") && !/^[a-zA-Z]:[\\/]/.test(value) && !value.includes(".."),
    "must be a path inside the target repo, relative to its root",
  );

export const RoundSchema = z.number().int().min(1, "rounds are numbered from 1");

export const FindingSchema = z
  .strictObject({
    id: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/, "finding id must be a lowercase slug"),
    source: FindingSourceSchema,
    confirmation_state: ConfirmationStateSchema,
    severity: SeveritySchema,
    class: z.string().min(1, "class names the bug category, for example heap-buffer-overflow"),
    file: repoRelativePath,
    line: z.number().int().positive().optional(),
    description: z.string().min(1),
    repro_command: z.string().min(1, "a finding is nothing without a repro command"),
    expected_secure_behavior: z.string().min(1),
    crash_artifact: repoRelativePath.optional(),
  })
  .superRefine((finding, ctx) => {
    if (finding.source === "fuzzer" && finding.crash_artifact === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["crash_artifact"],
        message: "a fuzzer finding must carry the minimized crash_artifact that reproduces it",
      });
    }
  });

export type Finding = z.infer<typeof FindingSchema>;

export const FindingsBatchSchema = z.strictObject({
  round: RoundSchema,
  findings: z.array(FindingSchema).superRefine((findings, ctx) => {
    const seen = new Set<string>();
    findings.forEach((finding, index) => {
      if (seen.has(finding.id)) {
        ctx.addIssue({
          code: "custom",
          path: [index, "id"],
          message: `duplicate finding id in batch: ${finding.id}`,
        });
      }
      seen.add(finding.id);
    });
  }),
});

export type FindingsBatch = z.infer<typeof FindingsBatchSchema>;
