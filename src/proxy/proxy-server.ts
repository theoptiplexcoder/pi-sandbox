import { existsSync, mkdirSync, rmSync } from "node:fs";
import type http from "node:http";
import { homedir } from "node:os";
import { join } from "node:path";
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
   * Local TCP port on loopback interface (for local tools/host).
   */
  httpPort: number;
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
}

/**
 * Starts the dual-listener proxy server:
 * 1. Unix Domain Socket (`socketPath`): mounted directly into `--unshare-net` containers.
 * 2. Loopback TCP Port (`httpPort`): accessible to host processes and test harnesses.
 */
export async function startProxyServer(
  optionsOrGetConfig: StartProxyOptions | (() => SandboxConfig),
  legacyOnUnknownDomain?: (domain: string, port: number) => Promise<boolean>,
): Promise<ProxyServerManager> {
  let getConfig: () => SandboxConfig;
  let onUnknownDomain: ((domain: string, port: number) => Promise<boolean>) | undefined;
  let onBlocked: ((domain: string, port: number, reason: string) => void) | undefined;
  let customSocketDir: string | undefined;

  if (typeof optionsOrGetConfig === "function") {
    getConfig = optionsOrGetConfig;
    onUnknownDomain = legacyOnUnknownDomain;
  } else {
    getConfig = optionsOrGetConfig.getConfig;
    onUnknownDomain = optionsOrGetConfig.onUnknownDomain;
    onBlocked = optionsOrGetConfig.onBlocked;
    customSocketDir = optionsOrGetConfig.customSocketDir;
  }

  // Create isolated runtime directory in user's secure cache or ~/.cache/pi-sandbox
  const baseCacheDir = customSocketDir ?? join(homedir(), ".cache", "pi-sandbox", "sockets");
  const socketDir = join(
    baseCacheDir,
    `proxy-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  );

  if (!existsSync(socketDir)) {
    mkdirSync(socketDir, { recursive: true, mode: 0o700 });
  }

  const socketPath = join(socketDir, "proxy.sock");

  // Create the proxy instances
  const httpProxy = createHttpProxy({
    getAllowedDomains: () => getConfig().network?.allowedDomains ?? [],
    getDeniedDomains: () => getConfig().network?.deniedDomains ?? [],
    onUnknownDomain,
    onBlocked,
  });

  const unixProxy = createHttpProxy({
    getAllowedDomains: () => getConfig().network?.allowedDomains ?? [],
    getDeniedDomains: () => getConfig().network?.deniedDomains ?? [],
    onUnknownDomain,
    onBlocked,
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
