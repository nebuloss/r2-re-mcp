/**
 * tools/types.ts — C type / struct support.
 *
 * Lets the agent teach r2 the firmware's structs (e.g. `struct hme_sys`) so that
 * read_mem / decompile can render fields by name instead of raw offsets. Three
 * tight tools: define a type, apply a type at an address, list known types.
 *
 * Backed by r2's type DB commands: `td` (define), `tp`/`tpx` (print-as-type),
 * `t`/`tj`/`tlj` (list). All output capped like every other tool.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager } from "../sessions.js";
import { guard, capped, resolveAddr, paginate } from "./common.js";

export function registerTypeTools(server: McpServer, sm: SessionManager): void {
  // define_type — apply a C type/struct definition via `td`.
  server.registerTool(
    "define_type",
    {
      title: "Define C type/struct",
      description:
        "Define a C type/struct in the session's type DB via `td \"<cdef>\"` " +
        '(e.g. td "struct hme_sys { ushort gate; uint flags; };"). Returns success or the ' +
        "r2 parse error. Persists with save_project. Use apply_type to render memory as the type.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        cdef: z
          .string()
          .describe('A C type/struct definition, e.g. \'struct hme_sys { ushort gate; };\'.'),
      },
    },
    async ({ target, cdef }) =>
      guard(async () => {
        const h = sm.get(target);
        const def = cdef.trim();
        // r2 splits commands on ';', which also separates struct members — so the
        // WHOLE command must be quoted (`"td <cdef>"`) per `td?`, NOT just the arg.
        const res = await h.cmd(`"td ${def}"`);
        const err = res && /error|parse|invalid|unexpected/i.test(res) ? res.trim() : "";
        if (err) return capped(`define_type failed: ${err}`);
        // VERIFY: pull the type name out of the cdef (e.g. "struct hme_sys {...}"
        // → hme_sys) and query it back with `ts <name>` to confirm it landed.
        const m = def.match(/\b(?:struct|union|enum|typedef)\s+([A-Za-z_]\w*)/);
        const structName = m?.[1];
        let verify = "";
        if (structName) {
          try {
            const ts = (await h.cmd(`ts ${structName}`)).trim();
            if (ts) verify = `\n${ts}`;
          } catch {
            /* verification is best-effort */
          }
        }
        const tail = res && res.trim() ? `\n${res.trim()}` : "";
        return capped(`type defined${structName ? ` (${structName})` : ""}.${tail}${verify}`);
      })
  );

  // apply_type — format/print memory at addr as a type (`tp`).
  server.registerTool(
    "apply_type",
    {
      title: "Apply type at address",
      description:
        "Format/print the memory at `addr` as `type` via `tp <type> @ <addr>` (the type must already " +
        "exist — see define_type / list_types). Returns the formatted, field-labelled view (capped). " +
        "Great for reading a struct instance, e.g. apply_type(type:'hme_sys', addr:0xeb700).",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
        type: z.string().describe("Type name to format as (e.g. 'hme_sys' or 'struct hme_sys')."),
      },
    },
    async ({ target, addr, type }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = await resolveAddr(h, addr);
        const t = type.trim();
        const out = await h.cmd(`tp ${t} @ ${a}`);
        if (!out || !out.trim()) {
          return capped(
            `(no output for tp ${t} @ ${a} — ensure the type exists (list_types) and is defined (define_type))`
          );
        }
        return capped(`# ${t} @ ${a}\n` + out);
      })
  );

  // list_types — compact list of known types (`tj`/`tlj`), optional filter.
  server.registerTool(
    "list_types",
    {
      title: "List types",
      description:
        "List known types in the session's type DB (`tj`, falling back to `tlj`/`t`). Optional " +
        "case-insensitive `filter` substring on the type name. Compact, capped.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        filter: z.string().optional().describe("Case-insensitive substring filter on the type name."),
      },
    },
    async ({ target, filter }) =>
      guard(async () => {
        const h = sm.get(target);
        // VALIDATED shape: `tj` → {"types":[{"type":"<name>","size":N,"format":"..."}]}.
        // (The old code parsed the wrong shape — Object.keys / .name — and found nothing.)
        let rows: { type: string; size?: number; format?: string }[] = [];
        try {
          const j = await h.cmdj("tj");
          if (j && Array.isArray(j.types)) {
            rows = j.types;
          }
        } catch {
          /* fall through to text */
        }
        const f = filter?.toLowerCase();
        const filtered = f ? rows.filter((r) => (r.type ?? "").toLowerCase().includes(f)) : rows;
        if (filtered.length === 0) {
          return capped(`(no types${filter ? ` matching "${filter}"` : ""})`);
        }
        const lines = filtered.map((r) => {
          const parts = [r.type];
          if (r.size !== undefined) parts.push(`size=${r.size}`);
          if (r.format) parts.push(`fmt=${r.format}`);
          return parts.join("  ");
        });
        const { slice, footer } = paginate(lines);
        return capped(`${filtered.length} type(s):\n` + slice.join("\n") + footer);
      })
  );
}
