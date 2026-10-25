import { existsSync, mkdirSync, rmSync } from "node:fs";
import type http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SandboxConfig } from "../config.ts";
import { createHttpProxy } from "./http-proxy.ts";

export interface ProxyServerManager {
  socketDir: string;
  httpPort: number;
  stop: () => Promise<void>;
}

export async function startProxyServer(
  getConfig: () => SandboxConfig,
  onUnknownDomain?: (domain: string, port: number) => Promise<boolean>,
): Promise<ProxyServerManager> {
  const socketDir = join(tmpdir(), `pi-sandbox-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  if (!existsSync(socketDir)) {
    mkdirSync(socketDir, { recursive: true, mode: 0o700 });
  }

  const httpProxy = createHttpProxy({
    getAllowedDomains: () => getConfig().network?.allowedDomains ?? [],
    getDeniedDomains: () => getConfig().network?.deniedDomains ?? [],
    onUnknownDomain,
  });

  const httpPort = await new Promise<number>((resolve) => {
    // Listen on 127.0.0.1 on a random available port
    httpProxy.listen(0, "127.0.0.1", () => {
      const addr = httpProxy.address();
      if (typeof addr === "object" && addr) {
        resolve(addr.port);
      } else {
        resolve(8080);
      }
    });
  });

  return {
    socketDir,
    httpPort,
    stop: async () => {
      await new Promise<void>((resolve) => {
        httpProxy.close(() => resolve());
      });
      try {
        if (existsSync(socketDir)) {
          rmSync(socketDir, { recursive: true, force: true });
        }
      } catch {
        // ignore
      }
    },
  };
}
