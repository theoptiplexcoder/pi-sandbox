import dns from "node:dns";
import http from "node:http";
import net, { BlockList } from "node:net";
import { isDomainAllowed } from "./domain-matcher.ts";

export interface HttpProxyOptions {
  getAllowedDomains: () => string[];
  getDeniedDomains: () => string[];
  onUnknownDomain?: (domain: string, port: number) => Promise<boolean>;
  onBlocked?: (domain: string, port: number, reason: string) => void;
  /**
   * Test-only override: allows connecting to loopback 127.0.0.1 for local test harnesses.
   * Never exposed to or readable from configuration files.
   */
  allowLoopbackForTests?: boolean;
}

// 1. Strict IP Blocklist covering Private, Loopback, Link-Local, Metadata, and Multicast
const IP_BLOCKLIST = new BlockList();
for (const [addr, prefix] of [
  ["0.0.0.0", 8], // Current network
  ["10.0.0.0", 8], // Private RFC1918
  ["100.64.0.0", 10], // Shared address space
  ["127.0.0.0", 8], // Loopback
  ["169.254.0.0", 16], // Link-Local / Cloud Metadata (169.254.169.254)
  ["172.16.0.0", 12], // Private RFC1918
  ["192.168.0.0", 16], // Private RFC1918
  ["224.0.0.0", 3], // Multicast & Reserved
] as const) {
  IP_BLOCKLIST.addSubnet(addr, prefix, "ipv4");
}
IP_BLOCKLIST.addAddress("::", "ipv6");
IP_BLOCKLIST.addAddress("::1", "ipv6");
IP_BLOCKLIST.addSubnet("fc00::", 7, "ipv6"); // Unique Local Address
IP_BLOCKLIST.addSubnet("fe80::", 10, "ipv6"); // Link-Local

/**
 * Checks whether an IP address is in a blocked subnet or reserved address space.
 */
export function isIpBlocked(ip: string, allowLoopback: boolean = false): boolean {
  if (allowLoopback && (ip === "127.0.0.1" || ip === "::1")) {
    return false;
  }

  // Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:192.168.1.1)
  if (ip.toLowerCase().startsWith("::ffff:")) {
    const v4Part = ip.slice(7);
    if (net.isIPv4(v4Part)) {
      return isIpBlocked(v4Part, allowLoopback);
    }
  }

  const type = net.isIPv6(ip) ? "ipv6" : "ipv4";
  return IP_BLOCKLIST.check(ip, type);
}

/**
 * Validates whether a target port is permitted for outbound egress.
 * Limits outbound tunneling strictly to standard web ports (80 and 443)
 * to prevent port-scanning, Redis exploitation (6379), or SSH tunneling (22).
 */
export function isPermittedPort(port: number, allowAnyPortForTests: boolean = false): boolean {
  if (allowAnyPortForTests) return true;
  return port === 80 || port === 443;
}

/**
 * Strict parser for host authorities (host:port).
 * Rejects integer IPs (e.g. 2130706433), octal/hex IPs (0x7f.1), and malformed strings.
 */
export function parseAuthority(rawAuthority: string): { host: string; port: number } | null {
  const trimmed = rawAuthority.trim();
  if (!trimmed) return null;

  let host: string;
  let port: number;

  if (trimmed.startsWith("[")) {
    // IPv6 bracket syntax: [::1]:443
    const closeBracket = trimmed.indexOf("]");
    if (closeBracket === -1) return null;
    host = trimmed.slice(1, closeBracket);
    const rest = trimmed.slice(closeBracket + 1);
    if (!rest.startsWith(":")) return null;
    port = parseInt(rest.slice(1), 10);
  } else {
    const parts = trimmed.split(":");
    if (parts.length !== 2) return null;
    host = parts[0];
    port = parseInt(parts[1], 10);
  }

  if (isNaN(port) || port <= 0 || port > 65535) return null;

  // Reject integer or numeric pseudo-IPs that are not valid standard IPs
  if (/^\d+$/.test(host) || /^0x[0-9a-fA-F]+/i.test(host)) {
    return null;
  }

  return { host, port };
}

/**
 * Creates a safe net.Socket connection that executes DNS resolution
 * and verifies all returned addresses against the SSRF blocklist.
 */
function connectUpstreamSafely(
  host: string,
  port: number,
  allowLoopback: boolean = false,
): net.Socket {
  // If host is already an IP literal, verify immediately (net.connect skips lookup for IP literals)
  if (net.isIP(host)) {
    if (isIpBlocked(host, allowLoopback)) {
      throw new Error(`[Security Sandbox] Blocked destination IP: ${host}`);
    }
  }

  const safeLookup: net.LookupFunction = (hostname, opts, cb) => {
    dns.lookup(hostname, { all: true }, (err, addrs) => {
      if (err) return cb(err as any, "" as any, 4 as any);
      // If ANY resolved address is in blocked subnet, reject the entire destination
      if (addrs.some((a) => isIpBlocked(a.address, allowLoopback))) {
        return cb(
          new Error(`[Security Sandbox] Blocked destination IP in DNS resolution for '${hostname}'`) as any,
          "" as any,
          4 as any,
        );
      }
      if (opts && typeof opts === "object" && (opts as any).all) {
        return (cb as any)(null, addrs);
      }
      return cb(null as any, addrs[0].address as any, addrs[0].family as any);
    });
  };

  return net.connect({
    host,
    port,
    lookup: safeLookup,
  });
}

/**
 * Creates an in-memory HTTP/HTTPS CONNECT proxy server.
 */
export function createHttpProxy(options: HttpProxyOptions): http.Server {
  const allowLoopback = options.allowLoopbackForTests ?? false;

  const server = http.createServer((req, res) => {
    try {
      if (!req.url) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Bad Request: missing URL");
        return;
      }

      let parsedUrl: URL;
      try {
        parsedUrl = req.url.startsWith("http")
          ? new URL(req.url)
          : new URL(`http://${req.headers.host}${req.url}`);
      } catch {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Bad Request: invalid URL");
        return;
      }

      const hostname = parsedUrl.hostname;
      const port = parseInt(parsedUrl.port || (parsedUrl.protocol === "https:" ? "443" : "80"), 10);

      // 1. Port restriction check
      if (!isPermittedPort(port, allowLoopback)) {
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end(`[claudelike-pisandbox] Port ${port} is not permitted for egress. Only ports 80/443 are allowed.`);
        return;
      }

      // 2. Direct IP literal check
      if (net.isIP(hostname) && isIpBlocked(hostname, allowLoopback)) {
        const reason = `[claudelike-pisandbox] Blocked connection to private/reserved IP: ${hostname} [blocked by Sandbox]`;
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end(reason);
        return;
      }

      // 3. Domain allowlist check
      const allowed = isDomainAllowed(
        hostname,
        options.getAllowedDomains(),
        options.getDeniedDomains(),
      );

      const doForward = () => {
        // Rewrite Host header from the parsed URL to prevent Host vs URL mismatches
        forwardHttpRequest(req, res, parsedUrl, allowLoopback);
      };

      if (allowed) {
        doForward();
      } else if (options.onUnknownDomain) {
        options
          .onUnknownDomain(hostname, port)
          .then((approved) => {
            if (approved) {
              doForward();
            } else {
              const reason = `[claudelike-pisandbox] Blocked connection to unapproved domain: ${hostname} [blocked by Sandbox]`;
              options.onBlocked?.(hostname, port, reason);
              res.writeHead(403, { "Content-Type": "text/plain" });
              res.end(reason);
            }
          })
          .catch((err) => {
            res.writeHead(500, { "Content-Type": "text/plain" });
            res.end(`Internal proxy error: ${String(err)}`);
          });
      } else {
        const reason = `[claudelike-pisandbox] Blocked connection to unapproved domain: ${hostname} [blocked by Sandbox]`;
        options.onBlocked?.(hostname, port, reason);
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end(reason);
      }
    } catch (err: unknown) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end(`Bad Request: ${err instanceof Error ? err.message : String(err)}`);
    }
  });

  // HTTPS CONNECT handler
  server.on("connect", (req, clientSocket, head) => {
    const authority = parseAuthority(req.url || "");
    if (!authority) {
      clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      clientSocket.destroy();
      return;
    }

    const { host, port } = authority;

    // 1. Port restriction check
    if (!isPermittedPort(port, allowLoopback)) {
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\nPort not permitted for egress. [blocked by Sandbox]\r\n");
      clientSocket.destroy();
      return;
    }

    // 2. Direct IP literal check
    if (net.isIP(host) && isIpBlocked(host, allowLoopback)) {
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\nBlocked destination IP. [blocked by Sandbox]\r\n");
      clientSocket.destroy();
      return;
    }

    const checkAndTunnel = (approved: boolean) => {
      if (!approved) {
        const reason = `[claudelike-pisandbox] Blocked connection to unapproved domain: ${host} [blocked by Sandbox]`;
        options.onBlocked?.(host, port, reason);
        clientSocket.write("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n" + reason);
        clientSocket.destroy();
        return;
      }

      let serverSocket: net.Socket;
      try {
        serverSocket = connectUpstreamSafely(host, port, allowLoopback);
      } catch (err: any) {
        clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n" + (err?.message || "Blocked IP"));
        clientSocket.destroy();
        return;
      }

      serverSocket.on("connect", () => {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head && head.length > 0) {
          serverSocket.write(head);
        }
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
      });

      serverSocket.on("error", () => {
        try {
          clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        } catch {}
        clientSocket.destroy();
      });

      clientSocket.on("error", () => {
        serverSocket.destroy();
      });

      clientSocket.on("close", () => serverSocket.destroy());
      serverSocket.on("close", () => clientSocket.destroy());
    };

    const allowed = isDomainAllowed(
      host,
      options.getAllowedDomains(),
      options.getDeniedDomains(),
    );

    if (allowed) {
      checkAndTunnel(true);
    } else if (options.onUnknownDomain) {
      options
        .onUnknownDomain(host, port)
        .then(checkAndTunnel)
        .catch(() => checkAndTunnel(false));
    } else {
      checkAndTunnel(false);
    }
  });

  return server;
}

function forwardHttpRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  parsedUrl: URL,
  allowLoopback: boolean,
) {
  const host = parsedUrl.hostname;
  const port = parseInt(parsedUrl.port || (parsedUrl.protocol === "https:" ? "443" : "80"), 10);

  // Strip hop-by-hop & proxy headers
  const headers = { ...req.headers };
  delete headers["proxy-connection"];
  delete headers["proxy-authorization"];
  delete headers["proxy-authenticate"];

  // Rewrite Host header from the validated URL
  headers.host = parsedUrl.host;

  let proxyReq: http.ClientRequest;
  try {
    proxyReq = http.request({
      hostname: host,
      port,
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers,
      lookup: (hostname, opts, cb) => {
        dns.lookup(hostname, { all: true }, (err, addrs) => {
          if (err) return cb(err as any, "" as any, 4 as any);
          if (addrs.some((a) => isIpBlocked(a.address, allowLoopback))) {
            return cb(new Error("Blocked destination IP in DNS resolution") as any, "" as any, 4 as any);
          }
          if (opts && typeof opts === "object" && (opts as any).all) {
            return (cb as any)(null, addrs);
          }
          return cb(null as any, addrs[0].address as any, addrs[0].family as any);
        });
      },
    }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      proxyRes.pipe(res);
    });
  } catch (err: any) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end(err?.message || "Blocked IP");
    return;
  }

  proxyReq.on("error", (err) => {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`Bad Gateway: ${err.message}`);
  });

  req.pipe(proxyReq);
}
