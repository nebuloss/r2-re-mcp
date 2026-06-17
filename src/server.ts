#!/usr/bin/env node
/**
 * server.ts — entrypoint for the r2-re-mcp streamable-http MCP server.
 *
 * Lean, stateful, token-disciplined radare2 MCP for the GT-BE98 / BCM6726b0
 * firmware RE workflow. Runs ALONGSIDE the stock r2mcp (which is on :8765) on a
 * NEW port (default 8766) so it never clobbers the existing service during trial.
 *
 * Transport: StreamableHTTPServerTransport (MCP streamable-http) on /mcp.
 * We run in STATELESS-HTTP mode at the transport layer (a fresh transport per
 * request, no MCP session id) — but the r2 ANALYSIS state is fully stateful and
 * process-global via the shared SessionManager, which is what actually matters
 * here. This keeps the HTTP layer simple and robust behind a reverse proxy.
 *
 * Env:
 *   R2_MCP_PORT     listen port (default 8766)
 *   RE_BINS         staged binaries dir (default /opt/re-bins)
 *   R2_PROJECT_DIR  r2 project dir (default $RE_BINS/.r2projects)
 *   LOG_LEVEL       error|warn|info|debug (default info)
 */

import http from "node:http";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SessionManager, RE_BINS, R2_PROJECT_DIR } from "./sessions.js";
import { registerTools } from "./tools.js";
import { log } from "./util.js";

const PORT = parseInt(process.env.R2_MCP_PORT ?? "8766", 10);
const HOST = "0.0.0.0";
const MCP_PATH = "/mcp";

const sessions = new SessionManager();

/** Build a fresh McpServer with all tools registered against the shared SessionManager. */
function buildServer(): McpServer {
  const server = new McpServer({
    name: "r2-re-mcp",
    version: "2.2.0",
  });
  registerTools(server, sessions);
  return server;
}

/** Read the full request body. */
function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const httpServer = http.createServer(async (req, res) => {
  try {
    // Simple health endpoint (handy for systemd / reverse-proxy checks).
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          server: "r2-re-mcp",
          openTargets: sessions.list(),
          reBins: RE_BINS,
          projectDir: R2_PROJECT_DIR,
        })
      );
      return;
    }

    const url = (req.url ?? "").split("?")[0];
    if (url !== MCP_PATH) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("not found — MCP endpoint is " + MCP_PATH);
      return;
    }

    // Stateless streamable-http: a fresh server+transport per request. The r2
    // session state is shared via the process-global SessionManager, so this is
    // safe and keeps us robust behind a reverse proxy that may not pin sessions.
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless mode
    });

    res.on("close", () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });

    await server.connect(transport);

    let parsedBody: unknown = undefined;
    if (req.method === "POST") {
      const raw = await readBody(req);
      if (raw) {
        try {
          parsedBody = JSON.parse(raw);
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              error: { code: -32700, message: "Parse error: invalid JSON body" },
              id: null,
            })
          );
          return;
        }
      }
    }

    await transport.handleRequest(req, res, parsedBody);
  } catch (e) {
    log.error("request handler error:", e);
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        })
      );
    } else {
      try {
        res.end();
      } catch {
        /* ignore */
      }
    }
  }
});

// --- graceful shutdown: close all r2 handles on SIGINT/SIGTERM -------------
let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info(`received ${signal}, shutting down…`);
  try {
    await sessions.closeAll();
  } catch (e) {
    log.error("error during session cleanup:", e);
  }
  httpServer.close(() => {
    log.info("http server closed; bye.");
    process.exit(0);
  });
  // Hard exit if close hangs.
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

httpServer.listen(PORT, HOST, () => {
  log.info(`r2-re-mcp listening on http://${HOST}:${PORT}${MCP_PATH}`);
  log.info(`  RE_BINS=${RE_BINS}  R2_PROJECT_DIR=${R2_PROJECT_DIR}`);
  log.info(`  (runs alongside stock r2mcp on :8765 — distinct port)`);
  void randomUUID; // (kept available for future stateful-session mode)
});
