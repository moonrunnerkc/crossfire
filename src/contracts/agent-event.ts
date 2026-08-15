import { z } from "zod";

export const STOP_REASONS = [
  "end_turn",
  "cancelled",
  "max_tokens",
  "max_turn_requests",
  "refusal",
] as const;

export const StopReasonSchema = z.enum(STOP_REASONS);

export type StopReason = z.infer<typeof StopReasonSchema>;

const jsonValue = z.json();

export const AgentEventSchema = z.discriminatedUnion("type", [
  z.strictObject({ type: z.literal("text"), text: z.string() }),
  z.strictObject({ type: z.literal("thinking"), text: z.string() }),
  z.strictObject({
    type: z.literal("tool_call"),
    call_id: z.string().min(1),
    name: z.string().min(1),
    input: jsonValue,
  }),
  z.strictObject({
    type: z.literal("tool_result"),
    call_id: z.string().min(1),
    status: z.enum(["ok", "error"]),
    output: z.string(),
  }),
  z.strictObject({ type: z.literal("done"), stop_reason: StopReasonSchema }),
  z.strictObject({
    type: z.literal("error"),
    message: z.string().min(1),
    code: z.string().min(1).optional(),
  }),
]);

export type AgentEvent = z.infer<typeof AgentEventSchema>;
