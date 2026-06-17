/**
 * tools/callgraph.ts — call-graph navigation tools.
 *
 * callers (who references this fn) and callees (what this fn calls). Both emit a
 * compact, capped one-line-per-edge view. Needs analysis (>= basic, ideally full).
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager } from "../sessions.js";
import { guard, capped, hex, resolveAddr } from "./common.js";

export function registerCallgraphTools(server: McpServer, sm: SessionManager): void {
  // callers — axtj @addr (sites that reference this function).
  server.registerTool(
    "callers",
    {
      title: "Callers",
      description:
        "Functions / sites that reference this function (addr-or-name) via `axtj`. Compact: " +
        "calling fn + call-site addr + type. Capped. Needs analysis (analyze depth:'full').",
      inputSchema: {
        target: z.string().describe("Open session name."),
        target_fn: z
          .union([z.string(), z.number()])
          .describe("Function address (firmware-VA) or name."),
      },
    },
    async ({ target, target_fn }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = await resolveAddr(h, target_fn);
        let rows: any[] = (await h.cmdj(`axtj @ ${a}`)) ?? [];
        if (!Array.isArray(rows)) rows = [];
        if (rows.length === 0) {
          return capped(`(no callers of ${a} — or analysis too light; try analyze depth:'full')`);
        }
        const lines = rows.slice(0, 200).map((r) => {
          const site = hex(r.from ?? r.addr);
          const fn = r.fcn_name ?? r.realname ?? "";
          const type = r.type ?? "?";
          const op = (r.opcode ?? r.disasm ?? "").toString().trim();
          return `${site}  [${type}]${fn ? "  in " + fn : ""}${op ? "  : " + op : ""}`;
        });
        let header = `${rows.length} caller-site(s) of ${a}`;
        if (rows.length > 200) header += " (showing first 200)";
        return capped(header + ":\n" + lines.join("\n"));
      })
  );

  // callees — afxj @addr (calls made FROM this function).
  server.registerTool(
    "callees",
    {
      title: "Callees",
      description:
        "Calls made FROM this function (addr-or-name) via `afxj`. Compact: call-site addr + " +
        "target addr/name + type. Capped. Needs analysis (analyze depth:'full').",
      inputSchema: {
        target: z.string().describe("Open session name."),
        target_fn: z
          .union([z.string(), z.number()])
          .describe("Function address (firmware-VA) or name."),
      },
    },
    async ({ target, target_fn }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = await resolveAddr(h, target_fn);
        let rows: any[] = (await h.cmdj(`afxj @ ${a}`)) ?? [];
        if (!Array.isArray(rows)) rows = [];
        // Prefer call edges, but keep all if afxj only returns calls anyway.
        const calls = rows.filter((r) => /call|CALL/.test(r.type ?? ""));
        const use = calls.length ? calls : rows;
        if (use.length === 0) {
          return capped(`(no callees from ${a} — or analysis too light; try analyze depth:'full')`);
        }
        const lines = use.slice(0, 200).map((r) => {
          const site = hex(r.from ?? r.at ?? r.addr);
          const to = hex(r.to ?? r.ref);
          const type = r.type ?? "?";
          const name = r.name ?? r.refname ?? "";
          return `${site} -> ${to}  [${type}]${name ? "  " + name : ""}`;
        });
        let header = `${use.length} callee edge(s) from ${a}`;
        if (use.length > 200) header += " (showing first 200)";
        return capped(header + ":\n" + lines.join("\n"));
      })
  );
}
