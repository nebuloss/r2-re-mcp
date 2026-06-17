/**
 * tools/triage.ts — overview / triage tools.
 *
 * info, sections, list_symbols, strings. All read r2 JSON and reformat into a
 * compact, capped key:value / one-line-per-row shape — never a raw blob.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager } from "../sessions.js";
import { guard, capped, hex, paginate } from "./common.js";

/** Shared pagination params for high-volume list tools. */
const pageParams = {
  offset: z.number().int().optional().describe("Pagination start index (default 0)."),
  limit: z.number().int().optional().describe("Max rows to return from offset."),
};

export function registerTriageTools(server: McpServer, sm: SessionManager): void {
  // info — consolidated binary metadata.
  server.registerTool(
    "info",
    {
      title: "Binary info",
      description:
        "Consolidated binary metadata: arch, bits, bintype, endian, base addr, size, and " +
        "entry points. Parses `ij` + `iej` (entrypoints), and also surfaces the live r2 " +
        "config `e asm.arch/asm.bits/asm.endian` + baddr/entry so RAW blobs (which have NO " +
        "bin metadata) still report arch/bits correctly. Compact key:value summary.",
      inputSchema: {
        target: z.string().describe("Open session name."),
      },
    },
    async ({ target }) =>
      guard(async () => {
        const h = sm.get(target);
        const ij = (await h.cmdj("ij")) ?? {};
        const bin = ij.bin ?? {};
        const core = ij.core ?? {};
        let entries: any[] = [];
        try {
          entries = (await h.cmdj("iej")) ?? [];
        } catch {
          /* ignore */
        }
        // Live r2 config — authoritative for RAW blobs that carry no bin metadata.
        const ev = async (v: string) => {
          try {
            return (await h.cmd(`e ${v}`)).trim();
          } catch {
            return "";
          }
        };
        const [asmArch, asmBits, asmEndian, cfgBaddr, cfgEntry] = await Promise.all([
          ev("asm.arch"),
          ev("asm.bits"),
          ev("asm.endian"),
          ev("bin.baddr"),
          ev("bin.entry"),
        ]);
        const lines: string[] = [];
        const put = (k: string, v: unknown) => {
          if (v !== undefined && v !== null && v !== "") lines.push(`${k}: ${v}`);
        };
        put("file", core.file);
        put("size", core.size ?? core.humansz);
        put("format", core.format ?? bin.bintype);
        put("arch", bin.arch);
        put("bits", bin.bits);
        put("endian", bin.endian);
        put("machine", bin.machine);
        put("os", bin.os);
        put("baddr", bin.baddr !== undefined ? hex(bin.baddr) : undefined);
        put("class", bin.class);
        put("lang", bin.lang);
        // asm.* config (esp. useful for RAW blobs with no bin.arch/bits above).
        put("asm.arch", asmArch);
        put("asm.bits", asmBits);
        put("asm.endian", asmEndian);
        if (!bin.baddr && cfgBaddr) put("cfg.baddr", cfgBaddr);
        if (cfgEntry) put("cfg.entry", cfgEntry);
        if (Array.isArray(entries) && entries.length) {
          const eps = entries
            .slice(0, 8)
            .map((e) => hex(e.vaddr ?? e.paddr ?? e.addr))
            .join(", ");
          put("entrypoints", `${entries.length} [${eps}${entries.length > 8 ? ", …" : ""}]`);
        }
        return capped(lines.join("\n") || "(no info available)");
      })
  );

  // sections — name / vaddr / vsize / perms.
  server.registerTool(
    "sections",
    {
      title: "Sections",
      description:
        "List sections/segments (`iSj`): name, vaddr, vsize, perms. Compact, capped.",
      inputSchema: {
        target: z.string().describe("Open session name."),
      },
    },
    async ({ target }) =>
      guard(async () => {
        const h = sm.get(target);
        const rows: any[] = (await h.cmdj("iSj")) ?? [];
        if (!Array.isArray(rows) || rows.length === 0) {
          return capped("(no sections — raw blob may have none; see `info`)");
        }
        const lines = rows.map((s) => {
          const name = s.name ?? "?";
          const va = hex(s.vaddr);
          const vsz = s.vsize !== undefined ? "0x" + Number(s.vsize).toString(16) : "?";
          const perm = s.perm ?? s.flags ?? "";
          return `${va}  vsize=${vsz}  ${perm}  ${name}`;
        });
        return capped(`${rows.length} section(s):\n` + lines.join("\n"));
      })
  );

  // list_symbols — symbols / imports / exports.
  server.registerTool(
    "list_symbols",
    {
      title: "List symbols/imports/exports",
      description:
        "List symbols (`isj`, default), imports (`iij`), or exports (`iEj`). Optional substring " +
        "`filter` on the name. Compact: name + addr + type. Capped.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        kind: z
          .enum(["symbols", "imports", "exports"])
          .optional()
          .describe("Which list, default 'symbols'."),
        filter: z.string().optional().describe("Case-insensitive substring filter on the name."),
        ...pageParams,
      },
    },
    async ({ target, kind, filter, offset, limit }) =>
      guard(async () => {
        const h = sm.get(target);
        const k = kind ?? "symbols";
        const cmd = k === "imports" ? "iij" : k === "exports" ? "iEj" : "isj";
        let rows: any[] = (await h.cmdj(cmd)) ?? [];
        if (!Array.isArray(rows)) rows = [];
        const f = filter?.toLowerCase();
        const filtered = f
          ? rows.filter((r) => (r.name ?? r.flagname ?? "").toLowerCase().includes(f))
          : rows;
        if (filtered.length === 0) {
          return capped(`(no ${k}${filter ? ` matching "${filter}"` : ""})`);
        }
        const { slice, footer } = paginate(filtered, offset, limit);
        const lines = slice.map((r) => {
          const name = r.name ?? r.flagname ?? "?";
          const addr = hex(r.vaddr ?? r.plt ?? r.paddr ?? r.addr);
          const type = r.type ?? r.bind ?? "";
          return `${addr}  ${type ? type + "  " : ""}${name}`;
        });
        const header = `${filtered.length} ${k}`;
        return capped(header + ":\n" + lines.join("\n") + footer);
      })
  );

  // strings — whole-binary string scan.
  server.registerTool(
    "strings",
    {
      title: "Strings",
      description:
        "Scan the WHOLE binary for strings (`izzj`). Optional case-insensitive `filter` substring " +
        "and `min` length (default 5). One line each: addr + string. Capped.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        filter: z.string().optional().describe("Case-insensitive substring filter."),
        min: z.number().int().optional().describe("Minimum string length, default 5."),
        ...pageParams,
      },
    },
    async ({ target, filter, min, offset, limit }) =>
      guard(async () => {
        const h = sm.get(target);
        const minLen = min ?? 5;
        let rows: any[] = (await h.cmdj("izzj")) ?? [];
        if (!Array.isArray(rows)) rows = [];
        const f = filter?.toLowerCase();
        const out = rows.filter((r) => {
          const s = r.string ?? "";
          if (typeof s !== "string") return false;
          if ((r.length ?? s.length) < minLen) return false;
          if (f && !s.toLowerCase().includes(f)) return false;
          return true;
        });
        if (out.length === 0) {
          return capped(`(no strings${filter ? ` matching "${filter}"` : ""} (min=${minLen}))`);
        }
        const { slice, footer } = paginate(out, offset, limit);
        const lines = slice.map((r) => {
          const addr = hex(r.vaddr ?? r.paddr ?? r.addr);
          const s = (r.string ?? "").replace(/\n/g, "\\n");
          return `${addr}  ${s}`;
        });
        const header = `${out.length} string(s)`;
        return capped(header + ":\n" + lines.join("\n") + footer);
      })
  );
}
