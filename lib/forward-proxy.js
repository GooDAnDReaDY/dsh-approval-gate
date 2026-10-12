// lib/forward-proxy.js
// Local HTTP/CONNECT Forward Proxy for Bash Network Egress Interception (#39).
// Binds to 127.0.0.1 and intercepts egress traffic from child processes (curl, python, node).
// Enforces sandbox network policies and blocks unauthorized hosts via HTTP and CONNECT tunnels.

import http from "node:http";
import net from "node:net";
import { checkNetworkAccess, parseDestination } from "./network-sandbox.js";

/**
 * Embedded forward proxy for intercepting subprocess egress (#39).
 */
export class LocalEgressProxy {
  /**
   * @param {{
   *   port?: number,
   *   sandboxMode?: string,
   *   whitelist?: string[],
   *   auditLogger?: any,
   *   logger?: any,
   * }} [options]
   */
  constructor(options = {}) {
    this.port = typeof options.port === "number" ? options.port : 0;
    this.sandboxMode = options.sandboxMode || "workspace-write";
    this.whitelist = Array.isArray(options.whitelist) ? [...options.whitelist] : [];
    this.auditLogger = options.auditLogger || null;
    this.logger = options.logger || null;

    this.server = null;
    this.listeningPort = 0;
    this.activeSockets = new Set();
  }

  /**
   * Starts the forward proxy server.
   * @returns {Promise<{ host: string, port: number }>}
   */
  async start() {
    if (this.server) {
      return { host: "127.0.0.1", port: this.listeningPort };
    }

    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this._handleHttpRequest(req, res);
      });

      this.server.on("connect", (req, clientSocket, head) => {
        this._handleConnectTunnel(req, clientSocket, head);
      });

      this.server.on("connection", (socket) => {
        this.activeSockets.add(socket);
        socket.once("close", () => this.activeSockets.delete(socket));
      });

      this.server.on("error", (err) => {
        if (this.logger) this.logger.error?.("LocalEgressProxy server error:", err);
        reject(err);
      });

      this.server.listen(this.port, "127.0.0.1", () => {
        const addr = this.server.address();
        this.listeningPort = typeof addr === "object" && addr ? addr.port : this.port;
        resolve({ host: "127.0.0.1", port: this.listeningPort });
      });
    });
  }

  /**
   * Stops the forward proxy and closes all active sockets.
   * @returns {Promise<void>}
   */
  async stop() {
    if (!this.server) return;

    return new Promise((resolve) => {
      for (const socket of this.activeSockets) {
        try {
          socket.destroy();
        } catch (_e) {}
      }
      this.activeSockets.clear();

      this.server.close(() => {
        this.server = null;
        this.listeningPort = 0;
        resolve();
      });
    });
  }

  /**
   * Returns proxy environment variables to inject into child processes.
   * @returns {{ HTTP_PROXY: string, HTTPS_PROXY: string, ALL_PROXY: string, NO_PROXY: string }}
   */
  getEnv() {
    if (!this.listeningPort) return {};
    const proxyUrl = `http://127.0.0.1:${this.listeningPort}`;
    return {
      HTTP_PROXY: proxyUrl,
      HTTPS_PROXY: proxyUrl,
      ALL_PROXY: proxyUrl,
      NO_PROXY: "127.0.0.1,localhost",
    };
  }

  /**
   * Checks whether access to destination is allowed under proxy rules.
   * @param {string} destination
   * @returns {ReturnType<typeof checkNetworkAccess>}
   */
  checkAccess(destination) {
    return checkNetworkAccess(destination, this.sandboxMode, {
      whitelist: this.whitelist,
    });
  }

  /**
   * @private
   */
  _handleHttpRequest(req, res) {
    const dest = req.url || req.headers.host || "";
    const access = this.checkAccess(dest);

    if (!access.allowed) {
      this._recordBlockedEgress(access.hostname, "HTTP", access.reason);
      res.writeHead(403, { "Content-Type": "text/plain", "X-Proxy-Blocked": "unauthorized-egress" });
      res.end(`403 Forbidden: Egress to ${access.hostname} blocked by security sandbox (${access.reason})\n`);
      return;
    }

    // Forward HTTP request
    try {
      const u = new URL(req.url);
      const options = {
        hostname: u.hostname,
        port: Number(u.port) || 80,
        path: `${u.pathname}${u.search}`,
        method: req.method,
        headers: req.headers,
      };

      const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res);
      });

      proxyReq.on("error", (err) => {
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end(`502 Bad Gateway: ${err.message}\n`);
      });

      req.pipe(proxyReq);
    } catch (err) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end(`400 Bad Request: ${err.message}\n`);
    }
  }

  /**
   * @private
   */
  _handleConnectTunnel(req, clientSocket, head) {
    const dest = req.url || "";
    const access = this.checkAccess(dest);

    if (!access.allowed) {
      this._recordBlockedEgress(access.hostname, "CONNECT", access.reason);
      clientSocket.write("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by security sandbox\n");
      clientSocket.destroy();
      return;
    }

    const { hostname, port } = parseDestination(dest);
    const targetPort = port || 443;

    const serverSocket = net.connect(targetPort, hostname, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length > 0) {
        serverSocket.write(head);
      }
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on("error", (_err) => {
      try {
        clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        clientSocket.destroy();
      } catch (_e) {}
    });

    clientSocket.on("error", (_err) => {
      try {
        serverSocket.destroy();
      } catch (_e) {}
    });
  }

  /**
   * @private
   */
  _recordBlockedEgress(host, protocol, reason) {
    if (this.auditLogger && typeof this.auditLogger.appendAuditLine === "function") {
      this.auditLogger.appendAuditLine({
        sessionId: "egress-proxy",
        decision: {
          verdict: "deny",
          stage: "P0",
          reason: `egress-proxy-blocked: ${reason}`,
          detail: `${protocol} to ${host}`,
        },
      });
    }
  }
}
