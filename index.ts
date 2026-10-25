import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function activate(pi: ExtensionAPI) {
  // Initialization entry point
  pi.on("session_start", async (_event, ctx) => {
    ctx.ui.setStatus("claudelike-pisandbox", "🔒 Sandbox Initializing");
  });
}
