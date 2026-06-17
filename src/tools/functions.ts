/**
 * tools/functions.ts — function listing / navigation tools.
 *
 * list_functions, function_info, disasm_function, rename. All Thumb-aware where
 * relevant and analysis-depth-aware (clear note when nothing is analyzed yet).
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager } from "../sessions.js";
import {
  guard,
  capped,
  text,
  fail,
  hex,
  resolveAddr,
  applyThumbHint,
  isThumbAt,
} from "./common.js";
import { addrArg } from "../util.js";

export function registerFunctionTools(server: McpServer, sm: SessionManager): void {
  // list_functions — aflj → compact rows.
  server.registerTool(
    "list_functions",
    {
      title: "List functions",
      description:
        "List analyzed functions (`aflj`): name, addr, size, nargs, nbbs. Optional case-insensitive " +
        "name `filter`. Capped. If empty, run analyze({depth:'full'}) first (light `aa` finds few).",
      inputSchema: {
        target: z.string().describe("Open session name."),
        filter: z.string().optional().describe("Case-insensitive substring filter on the name."),
      },
    },
    async ({ target, filter }) =>
      guard(async () => {
        const h = sm.get(target);
        let rows: any[] = (await h.cmdj("aflj")) ?? [];
        if (!Array.isArray(rows)) rows = [];
        if (rows.length === 0) {
          return capped(
            "(no functions analyzed yet — run analyze({ target, depth: 'full' }) or open with analysis:'full')"
          );
        }
        const f = filter?.toLowerCase();
        const filtered = f ? rows.filter((r) => (r.name ?? "").toLowerCase().includes(f)) : rows;
        if (filtered.length === 0) {
          return capped(`(no functions matching "${filter}")`);
        }
        const lines = filtered.slice(0, 400).map((r) => {
          const addr = hex(r.addr ?? r.offset);
          const size = r.size ?? 0;
          const nargs = r.nargs ?? 0;
          const nbbs = r.nbbs ?? 0;
          return `${addr}  size=${size}  args=${nargs}  bbs=${nbbs}  ${r.name ?? "?"}`;
        });
        let header = `${filtered.length} function(s)`;
        if (filtered.length > 400) header += " (showing first 400)";
        return capped(header + ":\n" + lines.join("\n"));
      })
  );

  // function_info — afij + afvj + caller/callee counts.
  server.registerTool(
    "function_info",
    {
      title: "Function info",
      description:
        "Compact summary of one function (addr-or-name): name, addr, size, bits (16=Thumb), " +
        "#bbs, args/locals (`afvj`), caller count (`axtj`), callee count (`afxj`).",
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
        const fj = await h.cmdj(`afij @ ${a}`);
        const info = Array.isArray(fj) ? fj[0] : fj;
        if (!info) {
          return fail(
            `no function at ${a} (run analyze({depth:'full'}) or 'af @ ${a}' via r2cmd).`
          );
        }
        let vars: any = {};
        try {
          vars = (await h.cmdj(`afvj @ ${a}`)) ?? {};
        } catch {
          /* ignore */
        }
        const nargs = (vars.reg?.length ?? 0) + (vars.stack?.filter((v: any) => v.kind === "arg")?.length ?? 0);
        const nlocals = vars.stack?.filter((v: any) => v.kind !== "arg")?.length ?? vars.bp?.length ?? 0;
        let callers = 0;
        try {
          const xt = await h.cmdj(`axtj @ ${a}`);
          callers = Array.isArray(xt) ? xt.length : 0;
        } catch {
          /* ignore */
        }
        let callees = 0;
        try {
          const xf = await h.cmdj(`afxj @ ${a}`);
          callees = Array.isArray(xf) ? xf.filter((x: any) => /call|CALL/.test(x.type ?? "")).length || xf.length : 0;
        } catch {
          /* ignore */
        }
        const lines = [
          `name:    ${info.name ?? "?"}`,
          `addr:    ${hex(info.addr ?? info.offset)}`,
          `size:    ${info.size ?? 0}`,
          `bits:    ${info.bits ?? "?"}${info.bits === 16 ? " (Thumb)" : ""}`,
          `bbs:     ${info.nbbs ?? "?"}`,
          `args:    ${info.nargs ?? nargs}`,
          `locals:  ${info.nlocals ?? nlocals}`,
          `callers: ${callers}`,
          `callees: ${callees}`,
        ];
        if (info.signature) lines.push(`sig:     ${info.signature}`);
        return capped(lines.join("\n"));
      })
  );

  // disasm_function — full function disasm, Thumb-aware.
  server.registerTool(
    "disasm_function",
    {
      title: "Disassemble whole function",
      description:
        "Full disassembly of the function (addr-or-name) via `pdf`. Thumb-aware: if the function " +
        "region is Thumb it applies `e asm.bits=16; ahb 16` over its extent first. Capped. " +
        "LIMITATION: mixed ARM/Thumb tails may still mis-decode — use thumb_disasm on a sub-addr.",
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
        const fj = await h.cmdj(`afij @ ${a}`);
        const info = Array.isArray(fj) ? fj[0] : fj;
        if (!info) {
          return fail(
            `no function at ${a} (run analyze({depth:'full'}) or 'af @ ${a}' via r2cmd).`
          );
        }
        const thumb = (await isThumbAt(h, a)) || info.bits === 16;
        if (thumb) {
          await applyThumbHint(h, a, info.size);
        }
        const out = await h.cmd(`pdf @ ${a}`);
        const header = `# ${info.name ?? a} @ ${a}${thumb ? " (Thumb)" : ""}\n`;
        return capped(header + (out && out.trim() ? out : "(no disassembly — function may be undefined)"));
      })
  );

  // rename — afn for function entry, else flag.
  server.registerTool(
    "rename",
    {
      title: "Rename (function or flag)",
      description:
        "Rename: if `addr` is a function entry, set the function name (`afn name @addr`); otherwise " +
        "set a flag (`f name @addr`). Persistence requires save_project.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
        name: z.string().describe("New name."),
      },
    },
    async ({ target, addr, name }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = addrArg(addr);
        // Is there a function whose entry is exactly here?
        let isFnEntry = false;
        try {
          const fj = await h.cmdj(`afij @ ${a}`);
          const info = Array.isArray(fj) ? fj[0] : fj;
          const fnAddr = info?.addr ?? info?.offset;
          if (typeof fnAddr === "number") {
            const here = (await h.cmd(`?vi ${a}`)).trim();
            isFnEntry = parseInt(here, 10) === fnAddr;
          }
        } catch {
          /* treat as non-function */
        }
        if (isFnEntry) {
          await h.cmd(`afn ${name} @ ${a}`);
          return text(`renamed function @ ${a} -> ${name} (call save_project to persist).`);
        }
        await h.cmd(`f ${name} @ ${a}`);
        return text(`set flag '${name}' @ ${a} (not a function entry; call save_project to persist).`);
      })
  );
}
