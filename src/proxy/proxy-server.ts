import { existsSync, mkdirSync, rmSync } from "node:fs";
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
 * Starts the Unix domain socket-first proxy server.
 * Creates an isolated runtime directory (`mode: 0o700`) under `~/.cache/pi-sandbox/sockets/`.
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

  // Create isolated runtime directory in user's secure cache (0700)
  const baseCacheDir = customSocketDir ?? join(homedir(), ".cache", "pi-sandbox", "sockets");
  const socketDir = join(
    baseCacheDir,
    `proxy-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  );

  if (!existsSync(socketDir)) {
    mkdirSync(socketDir, { recursive: true, mode: 0o700 });
  }

  const socketPath = join(socketDir, "proxy.sock");
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const bridgeScriptPath = join(currentDir, "bridge.py");

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
