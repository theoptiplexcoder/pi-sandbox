import http from "node:http";
import net from "node:net";
import { isDomainAllowed } from "./domain-matcher.ts";

export interface HttpProxyOptions {
  getAllowedDomains: () => string[];
  getDeniedDomains: () => string[];
  onUnknownDomain?: (domain: string, port: number) => Promise<boolean>;
}

/**
 * Creates an in-memory HTTP/HTTPS CONNECT proxy server.
 */
export function createHttpProxy(options: HttpProxyOptions): http.Server {
  const server = http.createServer((req, res) => {
    // Normal HTTP requests
    try {
      if (!req.url) {
        res.writeHead(400);
        res.end("Bad Request");
        return;
      }

      const urlObj = new URL(req.url);
      const hostname = urlObj.hostname;
      const port = parseInt(urlObj.port || "80", 10);

      const allowed = isDomainAllowed(
        hostname,
        options.getAllowedDomains(),
        options.getDeniedDomains(),
      );

      if (allowed) {
        forwardHttpRequest(req, res, urlObj);
      } else if (options.onUnknownDomain) {
        options.onUnknownDomain(hostname, port).then((approved) => {
          if (approved) {
            forwardHttpRequest(req, res, urlObj);
          } else {
            res.writeHead(403, { "Content-Type": "text/plain" });
            res.end(`[claudelike-pisandbox] Blocked connection to unapproved domain: ${hostname}`);
          }
        });
      } else {
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end(`[claudelike-pisandbox] Blocked connection to unapproved domain: ${hostname}`);
      }
    } catch {
      res.writeHead(400);
      res.end("Bad Request");
    }
  });

  // HTTPS CONNECT tunneling
  server.on("connect", (req, clientSocket, head) => {
    const [hostname, rawPort] = (req.url || "").split(":");
    const port = parseInt(rawPort || "443", 10);

    if (!hostname) {
      clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      clientSocket.destroy();
      return;
    }

    const checkAndTunnel = (approved: boolean) => {
      if (!approved) {
        clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
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
        clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        clientSocket.destroy();
      });

      clientSocket.on("error", () => {
        serverSocket.destroy();
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
      options.onUnknownDomain(hostname, port).then(checkAndTunnel);
    } else {
      checkAndTunnel(false);
    }
  });

  return server;
}

function forwardHttpRequest(req: http.IncomingMessage, res: http.ServerResponse, urlObj: URL) {
  const options: http.RequestOptions = {
    hostname: urlObj.hostname,
    port: urlObj.port || 80,
    path: urlObj.pathname + urlObj.search,
    method: req.method,
    headers: req.headers,
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("error", () => {
    res.writeHead(502);
    res.end("Bad Gateway");
  });

  req.pipe(proxyReq);
}
