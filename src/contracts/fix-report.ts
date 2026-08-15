import { z } from "zod";

import { RoundSchema } from "./finding.js";

export const AGENT_IDS = ["claude", "grok"] as const;

export const AgentIdSchema = z.enum(AGENT_IDS);

export type AgentId = z.infer<typeof AgentIdSchema>;

export const FixSchema = z.strictObject({
  finding_id: z.string().min(1),
  files_changed: z.array(z.string().min(1)).min(1, "a fix that changed no files is not a fix"),
  summary: z.string().min(1),
});

export const FixReportSchema = z.strictObject({
  round: RoundSchema,
  agent: AgentIdSchema,
  fixes: z.array(FixSchema).superRefine((fixes, ctx) => {
    const seen = new Set<string>();
    fixes.forEach((fix, index) => {
      if (seen.has(fix.finding_id)) {
        ctx.addIssue({
          code: "custom",
          path: [index, "finding_id"],
          message: `two fixes claim the same finding: ${fix.finding_id}`,
        });
      }
      seen.add(fix.finding_id);
    });
  }),
});

export type Fix = z.infer<typeof FixSchema>;
export type FixReport = z.infer<typeof FixReportSchema>;
