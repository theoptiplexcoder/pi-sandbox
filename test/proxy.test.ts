import { describe, expect, it } from "bun:test";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CONFIG, type SandboxConfig } from "../src/config.ts";
import { isDomainAllowed } from "../src/proxy/domain-matcher.ts";
import { startProxyServer, type ProxyServerManager } from "../src/proxy/proxy-server.ts";

describe("Phase 4: Network Isolation & Domain Filtering Proxy", () => {
  it("evaluates wildcard domains and denied precedence", () => {
    const allowed = ["github.com", "*.github.com", "*.npmjs.org"];
    const denied = ["malicious.github.com"];

    expect(isDomainAllowed("github.com", allowed, denied)).toBe(true);
    expect(isDomainAllowed("api.github.com", allowed, denied)).toBe(true);
    expect(isDomainAllowed("registry.npmjs.org", allowed, denied)).toBe(true);
    expect(isDomainAllowed("malicious.github.com", allowed, denied)).toBe(false);
    expect(isDomainAllowed("evil.com", allowed, denied)).toBe(false);
  });

  it("launches dual-listener proxy on TCP port and Unix domain socket", async () => {
    const manager = await startProxyServer(() => DEFAULT_CONFIG);

    expect(manager.httpPort).toBeGreaterThan(0);
    expect(manager.socketPath.endsWith("proxy.sock")).toBe(true);

    await manager.stop();
  });

  it("blocks unauthorized domains with HTTP 403 Forbidden", async () => {
    let blockedNotice = "";
    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: {
          allowedDomains: ["github.com"],
          deniedDomains: [],
        },
      }),
      onBlocked: (domain, _port, reason) => {
        blockedNotice = `${domain}: ${reason}`;
      },
    });

    try {
      // Connect to proxy via HTTP CONNECT request targeting unauthorized host
      const response = await new Promise<string>((resolve) => {
        const client = net.connect(manager.httpPort, "127.0.0.1", () => {
          client.write("CONNECT evil-c2-server.com:443 HTTP/1.1\r\nHost: evil-c2-server.com:443\r\n\r\n");
        });

        let data = "";
        client.on("data", (chunk) => {
          data += chunk.toString();
        });

        client.on("close", () => resolve(data));
      });

      expect(response).toContain("403 Forbidden");
      expect(response).toContain("Blocked connection to unapproved domain: evil-c2-server.com");
      expect(blockedNotice).toContain("evil-c2-server.com");
    } finally {
      await manager.stop();
    }
  });

  it("supports Unix domain socket tunneling", async () => {
    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: {
          allowedDomains: ["example.com"],
          deniedDomains: [],
        },
      }),
    });

    try {
      // Connect to the Unix domain socket directly
      const response = await new Promise<string>((resolve) => {
        const client = net.connect(manager.socketPath, () => {
          client.write("CONNECT unauthorized.org:443 HTTP/1.1\r\nHost: unauthorized.org:443\r\n\r\n");
        });

        let data = "";
        client.on("data", (chunk) => {
          data += chunk.toString();
        });

        client.on("close", () => resolve(data));
      });

      expect(response).toContain("403 Forbidden");
    } finally {
      await manager.stop();
    }
  });

  it("honors onUnknownDomain approval callback dynamically", async () => {
    let promptTriggered = false;

    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: {
          allowedDomains: ["github.com"],
        },
      }),
      onUnknownDomain: async (domain) => {
        if (domain === "approved-by-user.com") {
          promptTriggered = true;
          return true; // Approved by user
        }
        return false;
      },
    });

    try {
      // Simulated server that will receive connection
      const dummyServer = http.createServer((_req, res) => {
        res.end("hello from dummy server");
      });
      const dummyPort = await new Promise<number>((res) => {
        dummyServer.listen(0, "127.0.0.1", () => {
          res((dummyServer.address() as any).port);
        });
      });

      const response = await new Promise<string>((resolve) => {
        const client = net.connect(manager.httpPort, "127.0.0.1", () => {
          client.write(`CONNECT approved-by-user.com:${dummyPort} HTTP/1.1\r\nHost: approved-by-user.com:${dummyPort}\r\n\r\n`);
        });

        let data = "";
        client.on("data", (chunk) => {
          data += chunk.toString();
          client.destroy();
        });

        client.on("close", () => resolve(data));
      });

      expect(promptTriggered).toBe(true);
      dummyServer.close();
    } finally {
      await manager.stop();
    }
  });
});
