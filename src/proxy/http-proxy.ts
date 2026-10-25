import http from "node:http";
import net from "node:net";
import { isDomainAllowed } from "./domain-matcher.ts";

export interface HttpProxyOptions {
  getAllowedDomains: () => string[];
  getDeniedDomains: () => string[];
  onUnknownDomain?: (domain: string, port: number) => Promise<boolean>;
  onBlocked?: (domain: string, port: number, reason: string) => void;
}

/**
 * Creates an in-memory HTTP/HTTPS CONNECT proxy server.
 * Can bind to either a TCP port (for host/testing) or a Unix domain socket
 * (for mounting inside the bwrap container namespace).
 *
 * Security Model:
 * 1. Plain HTTP: Inspects request URL and Host header.
 * 2. HTTPS CONNECT: Inspects tunnel destination (host:port) prior to establishing TCP connection.
 * 3. Domain Whitelist: Exact domains, wildcards (*.github.com), deniedDomains precedence.
 * 4. Unlisted Domains: Calls onUnknownDomain callback for user authorization. If denied or headless, returns 403 Forbidden.
 * 5. Socket Error Handling: Destroys client and target sockets cleanly on disconnect/error without leaking descriptors.
 */
export function createHttpProxy(options: HttpProxyOptions): http.Server {
  const server = http.createServer((req, res) => {
    try {
      if (!req.url) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Bad Request: missing URL");
        return;
      }

      let hostname: string;
      let port: number;

      if (req.url.startsWith("http://") || req.url.startsWith("https://")) {
        const urlObj = new URL(req.url);
        hostname = urlObj.hostname;
        port = parseInt(urlObj.port || (urlObj.protocol === "https:" ? "443" : "80"), 10);
      } else {
        const hostHeader = req.headers.host || "";
        const [h, p] = hostHeader.split(":");
        hostname = h;
        port = parseInt(p || "80", 10);
      }

      if (!hostname) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Bad Request: unable to determine target host");
        return;
      }

      const allowed = isDomainAllowed(
        hostname,
        options.getAllowedDomains(),
        options.getDeniedDomains(),
      );

      if (allowed) {
        forwardHttpRequest(req, res, hostname, port);
      } else if (options.onUnknownDomain) {
        options.onUnknownDomain(hostname, port).then((approved) => {
          if (approved) {
            forwardHttpRequest(req, res, hostname, port);
          } else {
            const reason = `[claudelike-pisandbox] Blocked connection to unapproved domain: ${hostname}`;
            options.onBlocked?.(hostname, port, reason);
            res.writeHead(403, { "Content-Type": "text/plain" });
            res.end(reason);
          }
        }).catch((err) => {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end(`Internal proxy error: ${String(err)}`);
        });
      } else {
        const reason = `[claudelike-pisandbox] Blocked connection to unapproved domain: ${hostname}`;
        options.onBlocked?.(hostname, port, reason);
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end(reason);
      }
    } catch (err: unknown) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end(`Bad Request: ${err instanceof Error ? err.message : String(err)}`);
    }
  });

  // HTTPS CONNECT tunneling handler
  server.on("connect", (req, clientSocket, head) => {
    const rawUrl = req.url || "";
    const [hostname, rawPort] = rawUrl.split(":");
    const port = parseInt(rawPort || "443", 10);

    if (!hostname) {
      clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      clientSocket.destroy();
      return;
    }

    const checkAndTunnel = (approved: boolean) => {
      if (!approved) {
        const reason = `[claudelike-pisandbox] Blocked connection to unapproved domain: ${hostname}`;
        options.onBlocked?.(hostname, port, reason);
        clientSocket.write("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n" + reason);
        clientSocket.destroy();
        return;
      }

      const serverSocket = net.connect(port, hostname, () => {
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
        } catch {
          // Ignore write after end
        }
        clientSocket.destroy();
      });

      clientSocket.on("error", () => {
        serverSocket.destroy();
      });

      // Handle abort / close
      clientSocket.on("close", () => {
        serverSocket.destroy();
      });
      serverSocket.on("close", () => {
        clientSocket.destroy();
      });
    };

    const allowed = isDomainAllowed(
      hostname,
      options.getAllowedDomains(),
      options.getDeniedDomains(),
    );

    if (allowed) {
      checkAndTunnel(true);
    } else if (options.onUnknownDomain) {
      options.onUnknownDomain(hostname, port).then(checkAndTunnel).catch(() => checkAndTunnel(false));
    } else {
      checkAndTunnel(false);
    }
  });

  return server;
}

function forwardHttpRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  hostname: string,
  port: number,
) {
  const path = req.url?.startsWith("http") ? new URL(req.url).pathname + new URL(req.url).search : req.url;

  const options: http.RequestOptions = {
    hostname,
    port,
    path,
    method: req.method,
    headers: req.headers,
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (err) => {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`Bad Gateway: ${err.message}`);
  });

  req.pipe(proxyReq);
}
