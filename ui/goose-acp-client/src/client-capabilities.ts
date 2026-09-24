import type { GooseMcpHostCapabilities } from "./mcp-apps.js";

export interface GooseClientCapabilitiesMeta {
  warmachine?: {
    mcpHostCapabilities?: GooseMcpHostCapabilities;
    customNotifications?: boolean;
  };
}
