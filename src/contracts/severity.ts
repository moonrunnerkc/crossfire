import { z } from "zod";

export const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"] as const;

export const SeveritySchema = z.enum(SEVERITY_ORDER);

export type Severity = z.infer<typeof SeveritySchema>;

export function meetsSeverityBar(severity: Severity, bar: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(bar);
}
