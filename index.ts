import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { createSandboxedBashOps } from "./src/bash-operations.ts";
import { isBwrapAvailable } from "./src/bwrap.ts";
import { loadConfig, type SandboxConfig } from "./src/config.ts";
import { startProxyServer, type ProxyServerManager } from "./src/proxy/proxy-server.ts";
import { registerToolGuard } from "./src/tool-guard.ts";
import { promptPermission } from "./src/ui.ts";

export default function activate(pi: ExtensionAPI) {
  let activeConfig: SandboxConfig = loadConfig();
  let proxyManager: ProxyServerManager | null = null;
  let activeContext: ExtensionContext | null = null;

  // Session-granted allowances
  const sessionAllowedDomains = new Set<string>();
  const sessionAllowedPaths = new Set<string>();

  const getEffectiveConfig = (): SandboxConfig => {
    return {
      ...activeConfig,
      network: {
        ...activeConfig.network,
        allowedDomains: [
          ...(activeConfig.network?.allowedDomains ?? []),
          ...Array.from(sessionAllowedDomains),
        ],
      },
      filesystem: {
        ...activeConfig.filesystem,
        allowWrite: [
          ...(activeConfig.filesystem?.allowWrite ?? []),
          ...Array.from(sessionAllowedPaths),
        ],
      },
    };
  };

  // 1. In-Process Tool Guard (Node.js direct tools: read, write, edit)
  registerToolGuard(pi, () => ({
    config: getEffectiveConfig(),
    askPermission: async (message, path) => {
      if (!activeContext) return false;
      const decision = await promptPermission(activeContext, message, path);
      if (decision === "session" || decision === "project") {
        sessionAllowedPaths.add(path);
        return true;
      }
      return false;
    },
  }));

  // 2. Subprocess Bash Tool Replacement & user_bash hook
  const sandboxedBashOps = createSandboxedBashOps(() => ({
    config: getEffectiveConfig(),
    socketDir: proxyManager?.socketDir,
  }));

  const localCwd = process.cwd();
  const sandboxedBashTool = createBashTool(localCwd, { operations: sandboxedBashOps });

  pi.registerTool({
    ...sandboxedBashTool,
    label: "bash (sandboxed)",
    async execute(id, params, signal, onUpdate, ctx) {
      activeContext = ctx;
      if (!activeConfig.enabled) {
        const defaultBash = createBashTool(ctx.cwd);
        return defaultBash.execute(id, params, signal, onUpdate);
      }
      const instanceBashTool = createBashTool(ctx.cwd, { operations: sandboxedBashOps });
      return instanceBashTool.execute(id, params, signal, onUpdate);
    },
  });

  pi.on("user_bash", () => {
    if (!activeConfig.enabled) return;
    return { operations: sandboxedBashOps };
  });

  // 3. Lifecycle hooks
  pi.on("session_start", async (_event, ctx) => {
    activeContext = ctx;
    activeConfig = loadConfig(ctx.cwd);

    if (activeConfig.enabled === false) {
      ctx.ui.setStatus("claudelike-pisandbox", "⚠️ Sandbox Disabled");
      return;
    }

    if (!isBwrapAvailable()) {
      ctx.ui.setStatus("claudelike-pisandbox", "❌ Sandbox Error: bwrap missing");
      ctx.ui.notify(
        "[claudelike-pisandbox] bubblewrap ('bwrap') is not installed. Subprocess isolation disabled.",
        "warning",
      );
      return;
    }

    try {
      proxyManager = await startProxyServer(getEffectiveConfig, async (domain) => {
        if (!activeContext) return false;
        const decision = await promptPermission(
          activeContext,
          "Subprocess requested outbound connection",
          domain,
        );
        if (decision === "session" || decision === "project") {
          sessionAllowedDomains.add(domain);
          return true;
        }
        return false;
      });

      ctx.ui.setStatus("claudelike-pisandbox", "🔒 Sandbox Active (bwrap + proxy)");
    } catch (err) {
      console.error("[claudelike-pisandbox] Failed to start network proxy:", err);
      ctx.ui.setStatus("claudelike-pisandbox", "⚠️ Sandbox: proxy failed");
    }
  });

  pi.on("session_shutdown", async () => {
    if (proxyManager) {
      await proxyManager.stop();
      proxyManager = null;
    }
  });

  // 4. Slash Commands
  pi.registerCommand("sandbox", {
    description: "Display current security sandbox policy and allowances",
    handler: async (_args, ctx) => {
      const cfg = getEffectiveConfig();
      const output = [
        "🔒 claudelike-pisandbox status:",
        `  Status: ${cfg.enabled ? "Active" : "Disabled"}`,
        `  Bwrap available: ${isBwrapAvailable() ? "Yes" : "No"}`,
        `  Network proxy: ${proxyManager ? "Online" : "Offline"}`,
        "",
        "Filesystem Rules:",
        `  Allow Write: ${(cfg.filesystem?.allowWrite ?? []).join(", ")}`,
        `  Deny Read: ${(cfg.filesystem?.denyRead ?? []).join(", ")}`,
        `  Deny Write: ${(cfg.filesystem?.denyWrite ?? []).join(", ")}`,
        "",
        "Network Rules:",
        `  Allowed Domains: ${(cfg.network?.allowedDomains ?? []).join(", ")}`,
      ];
      ctx.ui.notify(output.join("\n"), "info");
    },
  });

  pi.registerCommand("sandbox-toggle", {
    description: "Toggle sandbox protection on or off for the current session",
    handler: async (_args, ctx) => {
      activeConfig.enabled = !activeConfig.enabled;
      ctx.ui.notify(
        `[claudelike-pisandbox] Sandbox is now ${activeConfig.enabled ? "ENABLED" : "DISABLED"}`,
        activeConfig.enabled ? "info" : "warning",
      );
      ctx.ui.setStatus(
        "claudelike-pisandbox",
        activeConfig.enabled ? "🔒 Sandbox Active" : "⚠️ Sandbox Disabled",
      );
    },
  });
}
