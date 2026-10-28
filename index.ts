import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createSandboxedBashOps } from "./src/bash-operations.ts";
import { isBwrapAvailable } from "./src/bwrap.ts";
import { loadConfig, type SandboxConfig } from "./src/config.ts";
import { isSecretPath } from "./src/policy.ts";
import { startProxyServer, type ProxyServerManager } from "./src/proxy/proxy-server.ts";
import { registerToolGuard } from "./src/tool-guard.ts";
import { promptPermission } from "./src/ui.ts";

/**
 * Saves a granted permission atomically to global user configuration `~/.pi/agent/sandbox.json`.
 * Enforces security invariants: rejects attempts to persist protected secrets.
 */
export function saveGlobalGrant(type: "domain" | "writePath", value: string): void {
  const globalDir = join(homedir(), ".pi", "agent");
  const configPath = join(globalDir, "sandbox.json");
  const tempPath = join(globalDir, `sandbox.json.tmp.${Date.now()}`);

  try {
    if (!existsSync(globalDir)) {
      mkdirSync(globalDir, { recursive: true });
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

    writeFileSync(tempPath, JSON.stringify(existing, null, 2) + "\n", "utf-8");
    renameSync(tempPath, configPath);
  } catch (err) {
    console.error(`[claudelike-pisandbox] Warning: Failed to save global grant to ${configPath}:`, err);
  }
}

/**
 * Saves a granted permission atomically to project-local `.pi/sandbox.json`.
 * Enforces security invariants: rejects attempts to persist protected secrets.
 */
export function saveProjectGrant(cwd: string, type: "domain" | "writePath", value: string): void {
  // Security Gate: Reject persisting mandatory secrets
  if (type === "writePath" && isSecretPath(value, [], cwd)) {
    throw new Error(`[Security Sandbox] Cannot save protected secret '${value}' to project configuration.`);
  }

  const piDir = join(cwd, ".pi");
  const configPath = join(piDir, "sandbox.json");
  const tempPath = join(piDir, `sandbox.json.tmp.${Date.now()}`);

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

    // Atomic write using temp file and renameSync
    writeFileSync(tempPath, JSON.stringify(existing, null, 2) + "\n", "utf-8");
    renameSync(tempPath, configPath);
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

  // 1. In-Process Tool Guard (Context is passed per-event, no global activeContext)
  registerToolGuard(pi, () => ({
    config: getEffectiveConfig(),
    askPermission: async (ctx, message, path) => {
      const decision = await promptPermission(ctx, message, path);
      if (decision === "always") {
        sessionAllowedPaths.add(path);
        saveGlobalGrant("writePath", path);
        activeConfig = loadConfig(ctx.cwd);
        return true;
      }
      if (decision === "project") {
        sessionAllowedPaths.add(path);
        saveProjectGrant(ctx.cwd || process.cwd(), "writePath", path);
        activeConfig = loadConfig(ctx.cwd);
        return true;
      }
      if (decision === "session") {
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
          const decision = await promptPermission(
            ctx,
            "Subprocess requested outbound network connection",
            domain,
          );
          if (decision === "always") {
            sessionAllowedDomains.add(domain);
            saveGlobalGrant("domain", domain);
            activeConfig = loadConfig(ctx.cwd);
            return true;
          }
          if (decision === "project") {
            sessionAllowedDomains.add(domain);
            saveProjectGrant(ctx.cwd || process.cwd(), "domain", domain);
            activeConfig = loadConfig(ctx.cwd);
            return true;
          }
          if (decision === "session") {
            sessionAllowedDomains.add(domain);
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
