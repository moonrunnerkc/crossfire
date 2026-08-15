import type { z } from "zod";

export function formatIssues(issues: readonly z.core.$ZodIssue[]): string {
  const lines: string[] = [];
  for (const issue of issues) {
    if (issue.code === "unrecognized_keys") {
      for (const key of issue.keys) {
        lines.push(`  ${[...issue.path, key].join(".")}: unrecognized key`);
      }
      continue;
    }
    const where = issue.path.length > 0 ? issue.path.join(".") : "<root>";
    lines.push(`  ${where}: ${issue.message}`);
  }
  return lines.join("\n");
}
