import { describe, expect, it } from "bun:test";
import http from "node:http";
import net from "node:net";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSandboxedBashOps } from "../src/bash-operations.ts";
import { isBwrapAvailable } from "../src/bwrap.ts";
import { DEFAULT_CONFIG } from "../src/config.ts";
import { isDomainAllowed } from "../src/proxy/domain-matcher.ts";
import { isIpBlocked, isPermittedPort, parseAuthority } from "../src/proxy/http-proxy.ts";
import { startProxyServer } from "../src/proxy/proxy-server.ts";

describe("Phase 4: Network Isolation & SSRF Defense", () => {
  it("detects and blocks all SSRF subnets and cloud metadata IPs", () => {
    // IPv4 private & reserved
    expect(isIpBlocked("127.0.0.1")).toBe(true);
    expect(isIpBlocked("10.0.0.1")).toBe(true);
    expect(isIpBlocked("172.16.0.1")).toBe(true);
    expect(isIpBlocked("192.168.1.1")).toBe(true);
    expect(isIpBlocked("169.254.169.254")).toBe(true); // AWS/GCP/Azure metadata
    expect(isIpBlocked("0.0.0.0")).toBe(true);

    // IPv6 private & loopback
    expect(isIpBlocked("::1")).toBe(true);
    expect(isIpBlocked("fc00::1")).toBe(true);
    expect(isIpBlocked("fe80::1")).toBe(true);
    expect(isIpBlocked("::ffff:127.0.0.1")).toBe(true); // IPv4-mapped loopback

    // Public IPs allowed
    expect(isIpBlocked("140.82.112.4")).toBe(false); // github.com
    expect(isIpBlocked("104.16.0.1")).toBe(false); // Cloudflare
  });

  it("restricts egress strictly to ports 80 and 443", () => {
    expect(isPermittedPort(80)).toBe(true);
    expect(isPermittedPort(443)).toBe(true);

    // Block non-web ports
    expect(isPermittedPort(22)).toBe(false); // SSH
    expect(isPermittedPort(6379)).toBe(false); // Redis
    expect(isPermittedPort(2375)).toBe(false); // Docker
    expect(isPermittedPort(5432)).toBe(false); // Postgres
  });

  it("strictly parses authorities and rejects numeric/octal/hex pseudo-IPs", () => {
    expect(parseAuthority("github.com:443")).toEqual({ host: "github.com", port: 443 });
    expect(parseAuthority("[::1]:443")).toEqual({ host: "::1", port: 443 });
    expect(parseAuthority("example.com:80")).toEqual({ host: "example.com", port: 80 });

    // Reject invalid port numbers
    expect(parseAuthority("example.com:0")).toBeNull();
    expect(parseAuthority("example.com:70000")).toBeNull();

    // Reject numeric/hex/octal obfuscated IPs
    expect(parseAuthority("2130706433:80")).toBeNull();
    expect(parseAuthority("0x7f.1:80")).toBeNull();
    expect(parseAuthority("invalid-authority")).toBeNull();
  });
});

describe("Phase 4: Proxy Server Live Request Filtering & Integration Tests", () => {
  it("blocks SSRF attempts to 127.0.0.1, 169.254.169.254, and [::1]", async () => {
    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: { allowedDomains: ["*"] },
      }),
    });

    try {
      // 1. Attempt CONNECT to 127.0.0.1:80
      const res1 = await new Promise<string>((resolve) => {
        const client = net.connect(manager.httpPort, "127.0.0.1", () => {
          client.write("CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n");
        });
        let data = "";
        client.on("data", (c) => (data += c.toString()));
        client.on("close", () => resolve(data));
      });
      expect(res1).toContain("403 Forbidden");

      // 2. Attempt CONNECT to 169.254.169.254:80 (cloud metadata)
      const res2 = await new Promise<string>((resolve) => {
        const client = net.connect(manager.httpPort, "127.0.0.1", () => {
          client.write("CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n");
        });
        let data = "";
        client.on("data", (c) => (data += c.toString()));
        client.on("close", () => resolve(data));
      });
      expect(res2).toContain("403 Forbidden");

      // 3. Attempt CONNECT to [::1]:80
      const res3 = await new Promise<string>((resolve) => {
        const client = net.connect(manager.httpPort, "127.0.0.1", () => {
          client.write("CONNECT [::1]:80 HTTP/1.1\r\nHost: [::1]:80\r\n\r\n");
        });
        let data = "";
        client.on("data", (c) => (data += c.toString()));
        client.on("close", () => resolve(data));
      });
      expect(res3).toContain("403 Forbidden");
    } finally {
      await manager.stop();
    }
  });

  it("blocks non-standard ports (e.g. port 22 or port 6379)", async () => {
    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: { allowedDomains: ["github.com"] },
      }),
    });

    try {
      const res = await new Promise<string>((resolve) => {
        const client = net.connect(manager.httpPort, "127.0.0.1", () => {
          client.write("CONNECT github.com:22 HTTP/1.1\r\nHost: github.com:22\r\n\r\n");
        });
        let data = "";
        client.on("data", (c) => (data += c.toString()));
        client.on("close", () => resolve(data));
      });

      expect(res).toContain("403 Forbidden");
      expect(res).toContain("Port not permitted");
    } finally {
      await manager.stop();
    }
  });

  it("rewrites Host header on plain HTTP requests to prevent Host vs URL mismatches", async () => {
    let receivedHostHeader = "";

    const dummyUpstream = http.createServer((req, res) => {
      receivedHostHeader = req.headers.host || "";
      res.end("ok");
    });

    const upstreamPort = await new Promise<number>((res) => {
      dummyUpstream.listen(0, "127.0.0.1", () => {
        res((dummyUpstream.address() as any).port);
      });
    });

    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: { allowedDomains: ["127.0.0.1"] },
      }),
      allowLoopbackForTests: true,
    });

    try {
      await new Promise<void>((resolve) => {
        const client = net.connect(manager.httpPort, "127.0.0.1", () => {
          client.write(
            `GET http://127.0.0.1:${upstreamPort}/test HTTP/1.1\r\nHost: spoofed-host.com\r\n\r\n`,
          );
        });
        client.on("data", () => {
          client.destroy();
          resolve();
        });
      });

      expect(receivedHostHeader).toBe(`127.0.0.1:${upstreamPort}`);
      dummyUpstream.close();
    } finally {
      await manager.stop();
    }
  });

  it("handles client abort during CONNECT without leaking sockets", async () => {
    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: { allowedDomains: ["github.com"] },
      }),
    });

    try {
      const client = net.connect(manager.httpPort, "127.0.0.1", () => {
        client.write("CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n");
        client.destroy();
      });

      await new Promise((r) => setTimeout(r, 100));
      expect(client.destroyed).toBe(true);
    } finally {
      await manager.stop();
    }
  });
});

describe("Phase 4: Real Container Subprocess Integration with Loopback Bridge", () => {
  const bwrapAvailable = isBwrapAvailable();

  it("routes curl from inside real bwrap through Unix socket bridge to allowed server", async () => {
    if (!bwrapAvailable) return;

    // Start a dummy upstream server
    const upstreamServer = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("SUCCESSFUL_PROXY_TUNNEL");
    });

    const upstreamPort = await new Promise<number>((res) => {
      upstreamServer.listen(0, "127.0.0.1", () => {
        res((upstreamServer.address() as any).port);
      });
    });

    // Start the Unix socket proxy
    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: {
          allowedDomains: ["127.0.0.1"],
        },
      }),
      allowLoopbackForTests: true,
    });

    const testDir = join(tmpdir(), `pi-sandbox-bridge-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let stdout = "";
    const ops = createSandboxedBashOps(() => ({
      config: {
        ...DEFAULT_CONFIG,
        network: {
          allowedDomains: ["127.0.0.1"],
        },
      },
      socketDir: manager.socketDir,
    }));

    try {
      // Execute curl inside bwrap using the transparent python loopback bridge
      const res = await ops.exec(
        `curl -s http://127.0.0.1:${upstreamPort}/`,
        testDir,
        {
          onData: (d) => {
            stdout += d.toString();
          },
        },
      );

      expect(res.exitCode).toBe(0);
      expect(stdout).toContain("SUCCESSFUL_PROXY_TUNNEL");
    } finally {
      await manager.stop();
      upstreamServer.close();
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  it("rejects unauthorized domains from inside real bwrap", async () => {
    if (!bwrapAvailable) return;

    const manager = await startProxyServer({
      getConfig: () => ({
        ...DEFAULT_CONFIG,
        network: {
          allowedDomains: ["github.com"],
          deniedDomains: ["unauthorized.com"],
        },
      }),
    });

    const testDir = join(tmpdir(), `pi-sandbox-bridge-unauth-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    let output = "";
    const ops = createSandboxedBashOps(() => ({
      config: {
        ...DEFAULT_CONFIG,
        network: {
          allowedDomains: ["github.com"],
        },
      },
      socketDir: manager.socketDir,
    }));

    try {
      const res = await ops.exec(
        "curl -s -i http://unauthorized.com/ 2>&1",
        testDir,
        {
          onData: (d) => {
            output += d.toString();
          },
        },
      );

      expect(output).toContain("403 Forbidden");
      expect(output).toContain("Blocked connection to unapproved domain: unauthorized.com");
    } finally {
      await manager.stop();
      rmSync(testDir, { recursive: true, force: true });
    }
  });
});
