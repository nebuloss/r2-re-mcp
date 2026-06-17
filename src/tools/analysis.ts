/**
 * tools/analysis.ts — analysis-control tools.
 *
 * Fixes a known gap: the xref/function tools return nothing under a light `aa`.
 * `analyze` lets the agent deepen analysis on demand; `close_target` frees the
 * r2 handle.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager } from "../sessions.js";
import { guard, capped, text } from "./common.js";

export function registerAnalysisTools(server: McpServer, sm: SessionManager): void {
  // analyze — deepen analysis on an already-open target.
  server.registerTool(
    "analyze",
    {
      title: "Analyze (deepen)",
      description:
        "Run radare2 analysis on an open target to populate functions/xrefs. " +
        "depth: 'basic'=aa | 'full'=aaa | 'refs'=aar then aac (xrefs+calls) | " +
        "'emu'=aae/aaae (ESIL-assisted). The function/xref/callgraph tools need at " +
        "least 'basic', ideally 'full'. NOTE: can be slow on a ~5MB blob (aaa/emu).",
      inputSchema: {
        target: z.string().describe("Open session name."),
        depth: z
          .enum(["basic", "full", "refs", "emu"])
          .optional()
          .describe("Analysis depth, default 'full'."),
      },
    },
    async ({ target, depth }) =>
      guard(async () => {
        const h = sm.get(target);
        const d = depth ?? "full";
        if (d === "basic") {
          await h.cmd("aa");
        } else if (d === "full") {
          await h.cmd("aaa");
        } else if (d === "refs") {
          await h.cmd("aar");
          await h.cmd("aac");
        } else {
          // emu: aae (ESIL emulate-all) then aaae (analyze esil references).
          await h.cmd("aae");
          await h.cmd("aaae");
        }
        let count = 0;
        try {
          const j = await h.cmdj("aflj");
          count = Array.isArray(j) ? j.length : 0;
        } catch {
          /* ignore */
        }
        return capped(`analysis '${d}' done on "${target}": ${count} function(s).`);
      })
  );

  // close_target — free the r2 handle.
  server.registerTool(
    "close_target",
    {
      title: "Close target",
      description:
        "Close an open session and free its r2 handle. In-session flags/comments are " +
        "lost unless save_project was called first.",
      inputSchema: {
        target: z.string().describe("Open session name to close."),
      },
    },
    async ({ target }) =>
      guard(async () => {
        const closed = await sm.close(target);
        return closed
          ? text(`closed "${target}".`)
          : text(`"${target}" was not open (nothing to close).`);
      })
  );
}
