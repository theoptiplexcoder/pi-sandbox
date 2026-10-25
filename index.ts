import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createSandboxedBashOps } from "./src/bash-operations.ts";
import { isBwrapAvailable } from "./src/bwrap.ts";
import { loadConfig, type SandboxConfig } from "./src/config.ts";
import { startProxyServer, type ProxyServerManager } from "./src/proxy/proxy-server.ts";
import { registerToolGuard } from "./src/tool-guard.ts";
import { promptPermission } from "./src/ui.ts";

/**
 * Saves a granted permission permanently to project-local `.pi/sandbox.json`.
 */
export function saveProjectGrant(cwd: string, type: "domain" | "writePath", value: string): void {
  const piDir = join(cwd, ".pi");
  const configPath = join(piDir, "sandbox.json");

  try {
    if (!existsSync(piDir)) {
      mkdirSync(piDir, { recursive: true });
    }

    let existing: Partial<SandboxConfig> = {};
    if (existsSync(configPath)) {
      try {
        existing = JSON.parse(readFileSync(configPath, "utf-8"));
      } catch {
        existing = {};
      }
    }

    if (type === "domain") {
      const allowed = new Set(existing.network?.allowedDomains ?? []);
      allowed.add(value);
      existing.network = {
        ...existing.network,
        allowedDomains: Array.from(allowed),
      };
    } else if (type === "writePath") {
      const allowed = new Set(existing.filesystem?.allowWrite ?? []);
      allowed.add(value);
      existing.filesystem = {
        ...existing.filesystem,
        allowWrite: Array.from(allowed),
      };
    }

    writeFileSync(configPath, JSON.stringify(existing, null, 2) + "\n", "utf-8");
  } catch (err) {
    console.error(`[claudelike-pisandbox] Warning: Failed to save grant to ${configPath}:`, err);
  }
}

/**
 * Extension entry point activated by Pi harness.
 */
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

  // 1. In-Process Tool Guard (Node.js direct tools: read, write, edit, grep, find, ls)
  registerToolGuard(pi, () => ({
    config: getEffectiveConfig(),
    askPermission: async (message, path) => {
      if (!activeContext) return false;
      const decision = await promptPermission(activeContext, message, path);
      if (decision === "session") {
        sessionAllowedPaths.add(path);
        return true;
      }
      if (decision === "project") {
        sessionAllowedPaths.add(path);
        saveProjectGrant(activeContext.cwd || process.cwd(), "writePath", path);
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

  pi.on("user_bash", (_event, ctx) => {
    activeContext = ctx;
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
      proxyManager = await startProxyServer({
        getConfig: getEffectiveConfig,
        onUnknownDomain: async (domain) => {
          if (!activeContext) return false;
          const decision = await promptPermission(
            activeContext,
            "Subprocess requested outbound network connection",
            domain,
          );
          if (decision === "session") {
            sessionAllowedDomains.add(domain);
            return true;
          }
          if (decision === "project") {
            sessionAllowedDomains.add(domain);
            saveProjectGrant(activeContext.cwd || process.cwd(), "domain", domain);
            return true;
          }
          return false;
        },
      });

      ctx.ui.setStatus("claudelike-pisandbox", "🔒 Sandbox Active");
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
    description: "Display current security sandbox policy, allowed domains, and grants",
    handler: async (_args, ctx) => {
      const cfg = getEffectiveConfig();
      const output = [
        "🔒 claudelike-pisandbox Status & Active Policies:",
        `  Status: ${cfg.enabled ? "ACTIVE" : "DISABLED"}`,
        `  Bubblewrap OS Containment: ${isBwrapAvailable() ? "Available (Kernel Enforced)" : "MISSING"}`,
        `  Domain Filtering Proxy: ${proxyManager ? "Online (Unix Socket Bridge)" : "Offline"}`,
        "",
        "Filesystem Policy:",
        `  Allow Write: ${(cfg.filesystem?.allowWrite ?? []).join(", ") || "(none)"}`,
        `  Deny Read: ${(cfg.filesystem?.denyRead ?? []).slice(0, 10).join(", ")}... (${cfg.filesystem?.denyRead?.length ?? 0} total)`,
        `  Deny Write: ${(cfg.filesystem?.denyWrite ?? []).slice(0, 10).join(", ")}... (${cfg.filesystem?.denyWrite?.length ?? 0} total)`,
        "",
        "Network Policy:",
        `  Allowed Domains: ${(cfg.network?.allowedDomains ?? []).join(", ") || "(none)"}`,
        `  Session Grants: ${Array.from(sessionAllowedDomains).join(", ") || "(none)"}`,
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
