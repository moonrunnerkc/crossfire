export { AcpAgentHandle } from "./acp-client.js";
export type { AcpClientConfig } from "./acp-client.js";

export { TransportError, normalizeSessionUpdate, toolAccessOf } from "./events.js";

export { ACCESS_DENIED, registerClientHandlers } from "./handlers.js";
export { tapStreams } from "./tap.js";
export type { Traffic, TrafficListener } from "./tap.js";
export type { DeniedAccess, HandlerHooks } from "./handlers.js";

export type { AgentHandle, NewSessionOptions, TransportMode } from "./types.js";
