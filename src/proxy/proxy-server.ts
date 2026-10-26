import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import type http from "node:http";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { SandboxConfig } from "../config.ts";
import { createHttpProxy } from "./http-proxy.ts";

export interface ProxyServerManager {
  /**
   * Directory where the Unix domain socket is bound.
   * Bound into bubblewrap container at `/run/pi-sandbox`.
   */
  socketDir: string;
  /**
   * Path to the Unix domain socket for IPC tunneling.
   */
  socketPath: string;
  /**
   * Local TCP port on loopback interface (optional/testing).
   */
  httpPort: number;
  /**
   * Path to the Python loopback bridge script.
   */
  bridgeScriptPath: string;
  /**
   * Gracefully shuts down the proxy server and removes the socket directory.
   */
  stop: () => Promise<void>;
}

export interface StartProxyOptions {
  getConfig: () => SandboxConfig;
  onUnknownDomain?: (domain: string, port: number) => Promise<boolean>;
  onBlocked?: (domain: string, port: number, reason: string) => void;
  customSocketDir?: string;
  allowLoopbackForTests?: boolean;
}

/**
 * Startup sweep: inspects the proxy sockets cache directory and cleans up stale socket directories
 * left behind by crashed or killed processes.
 * Checks the PID encoded in the directory name: if process.kill(pid, 0) fails, the owner is dead.
 */
export function sweepStaleSocketDirs(baseCacheDir: string): void {
  if (!existsSync(baseCacheDir)) return;

  try {
    const entries = readdirSync(baseCacheDir);
    for (const entry of entries) {
      if (!entry.startsWith("proxy-pid-")) continue;

      const fullPath = join(baseCacheDir, entry);
      const parts = entry.split("-");
      // Format: proxy-pid-<pid>-<timestamp>-<rand>
      if (parts.length >= 3) {
        const pid = parseInt(parts[2], 10);
        if (!isNaN(pid) && pid > 0) {
          let isAlive = false;
          try {
            // Signal 0 tests for process existence
            process.kill(pid, 0);
            isAlive = true;
          } catch {
            isAlive = false; // Dead process
          }

          if (!isAlive) {
            try {
              rmSync(fullPath, { recursive: true, force: true });
            } catch {
              // Ignore sweep cleanup error
            }
          }
        }
      }
    }
  } catch {
    // Ignore sweep read errors
  }
}

/**
 * Starts the Unix domain socket-first proxy server.
 * Creates an isolated runtime directory (`mode: 0o700`) named with current PID for safe sweep recovery.
 */
export async function startProxyServer(
  optionsOrGetConfig: StartProxyOptions | (() => SandboxConfig),
  legacyOnUnknownDomain?: (domain: string, port: number) => Promise<boolean>,
): Promise<ProxyServerManager> {
  let getConfig: () => SandboxConfig;
  let onUnknownDomain: ((domain: string, port: number) => Promise<boolean>) | undefined;
  let onBlocked: ((domain: string, port: number, reason: string) => void) | undefined;
  let customSocketDir: string | undefined;
  let allowLoopbackForTests: boolean = false;

  if (typeof optionsOrGetConfig === "function") {
    getConfig = optionsOrGetConfig;
    onUnknownDomain = legacyOnUnknownDomain;
  } else {
    getConfig = optionsOrGetConfig.getConfig;
    onUnknownDomain = optionsOrGetConfig.onUnknownDomain;
    onBlocked = optionsOrGetConfig.onBlocked;
    customSocketDir = optionsOrGetConfig.customSocketDir;
    allowLoopbackForTests = optionsOrGetConfig.allowLoopbackForTests ?? false;
  }

  // Base cache directory: Prefer XDG_RUNTIME_DIR if available, else ~/.cache/pi-sandbox/sockets
  const baseCacheDir =
    customSocketDir ??
    process.env.XDG_RUNTIME_DIR
      ? join(process.env.XDG_RUNTIME_DIR!, "pi-sandbox-sockets")
      : join(homedir(), ".cache", "pi-sandbox", "sockets");

  // 1. Run startup sweep for stale dead-process sockets
  sweepStaleSocketDirs(baseCacheDir);

  // 2. Create isolated runtime directory for this PID (0700)
  const socketDir = join(
    baseCacheDir,
    `proxy-pid-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  );

  if (!existsSync(socketDir)) {
    mkdirSync(socketDir, { recursive: true, mode: 0o700 });
  }

  const socketPath = join(socketDir, "proxy.sock");
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const bridgeScriptPath = join(currentDir, "bridge.py");

  // Synchronous exit cleanup hook for ungraceful exits
  const exitCleanupHook = () => {
    try {
      if (existsSync(socketDir)) {
        rmSync(socketDir, { recursive: true, force: true });
      }
    } catch {
      // Best effort cleanup on process exit
    }
  };
  process.once("exit", exitCleanupHook);

  // Create the proxy instances
  const httpProxy = createHttpProxy({
    getAllowedDomains: () => getConfig().network?.allowedDomains ?? [],
    getDeniedDomains: () => getConfig().network?.deniedDomains ?? [],
    onUnknownDomain,
    onBlocked,
    allowLoopbackForTests,
  });

  const unixProxy = createHttpProxy({
    getAllowedDomains: () => getConfig().network?.allowedDomains ?? [],
    getDeniedDomains: () => getConfig().network?.deniedDomains ?? [],
    onUnknownDomain,
    onBlocked,
    allowLoopbackForTests,
  });

  // 1. Listen on local TCP loopback
  const httpPort = await new Promise<number>((resolve, reject) => {
    httpProxy.listen(0, "127.0.0.1", () => {
      const addr = httpProxy.address();
      if (typeof addr === "object" && addr) {
        resolve(addr.port);
      } else {
        resolve(8080);
      }
    });
    httpProxy.on("error", reject);
  });

  // 2. Listen on Unix domain socket for container namespace
  await new Promise<void>((resolve, reject) => {
    unixProxy.listen(socketPath, () => {
      resolve();
    });
    unixProxy.on("error", reject);
  });

  return {
    socketDir,
    socketPath,
    httpPort,
    bridgeScriptPath,
    stop: async () => {
      process.removeListener("exit", exitCleanupHook);
      await Promise.all([
        new Promise<void>((resolve) => httpProxy.close(() => resolve())),
        new Promise<void>((resolve) => unixProxy.close(() => resolve())),
      ]);
      try {
        if (existsSync(socketDir)) {
          rmSync(socketDir, { recursive: true, force: true });
        }
      } catch {
        // Ignore cleanup errors
      }
    },
  };
}
