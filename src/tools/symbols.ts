/**
 * tools/symbols.ts — symbol import (bridge from Ghidra).
 *
 * The firmware blob carries NO symbols — every function shows up as
 * `fcn.000f335c`. The team's real names live in the bethington Ghidra project.
 * `import_symbols` lets you push those names into the r2 session as flags (and,
 * for functions, define + name the function) so every other tool (xrefs,
 * decompile, callgraph) renders readable names.
 *
 * CANONICAL SOURCE: the names come from the bethington Ghidra project — export
 * them separately (e.g. a Ghidra script dumping {name, addr, kind}) into a JSON
 * or CSV file under RE_BINS, then point `import_symbols({ file })` at it.
 *
 * ADDRESSING: addresses here are firmware-VA directly (NO +0x10000 skew). If the
 * Ghidra export carries the +0x10000 image-base, strip it during export.
 */

import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SessionManager, RE_BINS } from "../sessions.js";
import { guard, capped, fail } from "./common.js";
import { addrArg } from "../util.js";

interface SymEntry {
  name: string;
  addr: string | number;
  kind?: "function" | "label";
}

/** r2 flag names must be [A-Za-z0-9_.]; replace anything else with '_'. */
function sanitizeName(name: string): string {
  return String(name).trim().replace(/[^A-Za-z0-9_.]/g, "_");
}

/** Parse a symbols file: JSON array of {name,addr,kind} OR CSV `name,addr[,kind]`. */
function parseFile(filePath: string): SymEntry[] {
  const raw = fs.readFileSync(filePath, "utf8");
  const trimmed = raw.trim();
  // JSON array path.
  if (trimmed.startsWith("[")) {
    const arr = JSON.parse(trimmed);
    if (!Array.isArray(arr)) throw new Error("symbols JSON must be an array");
    return arr as SymEntry[];
  }
  // CSV path: one `name,addr[,kind]` per line; '#' comments and blanks skipped.
  const out: SymEntry[] = [];
  for (const line of trimmed.split(/\r?\n/)) {
    const l = line.trim();
    if (!l || l.startsWith("#")) continue;
    const parts = l.split(",").map((p) => p.trim());
    if (parts.length < 2) continue;
    const [name, addr, kind] = parts;
    out.push({ name, addr, kind: kind === "function" ? "function" : kind === "label" ? "label" : undefined });
  }
  return out;
}

export function registerSymbolTools(server: McpServer, sm: SessionManager): void {
  server.registerTool(
    "import_symbols",
    {
      title: "Import symbols (Ghidra bridge)",
      description:
        "Import names/addresses into the session so every tool renders readable names instead " +
        "of fcn.000xxxxx. Provide `symbols` (inline array of {name, addr, kind?}) and/or `file` " +
        "(path under RE_BINS if relative; a JSON array of the same shape, OR a CSV `name,addr[,kind]`). " +
        "For each entry: sets a flag `f <name> @ <addr>`; if kind=='function' also defines+names the " +
        "function (`af`/`afn`). Names are sanitized r2-flag-safe ([A-Za-z0-9_.]). Addresses are " +
        "firmware-VA directly (NO +0x10000). CANONICAL SOURCE: the bethington Ghidra project — export " +
        "the {name,addr,kind} list from there separately. Call save_project afterward to persist.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        file: z
          .string()
          .optional()
          .describe("Path to a JSON array or CSV of symbols (resolved under RE_BINS if relative)."),
        symbols: z
          .array(
            z.object({
              name: z.string(),
              addr: z.union([z.string(), z.number()]),
              kind: z.enum(["function", "label"]).optional(),
            })
          )
          .optional()
          .describe("Inline symbol entries: {name, addr, kind?}."),
      },
    },
    async ({ target, file, symbols }) =>
      guard(async () => {
        const h = sm.get(target);
        const entries: SymEntry[] = [];
        if (Array.isArray(symbols)) entries.push(...symbols);
        if (file) {
          const fp = path.isAbsolute(file) ? file : path.join(RE_BINS, file);
          if (!fs.existsSync(fp)) {
            return fail(`symbols file not found: ${fp} (RE_BINS=${RE_BINS}).`);
          }
          entries.push(...parseFile(fp));
        }
        if (entries.length === 0) {
          return fail("import_symbols: provide at least one of `symbols` (inline) or `file`.");
        }

        let imported = 0;
        let functions = 0;
        const skipped: string[] = [];
        for (const e of entries) {
          const rawName = e?.name;
          const addr = e?.addr;
          if (!rawName || addr === undefined || addr === null || addr === "") {
            skipped.push(`(missing name/addr): ${JSON.stringify(e)}`);
            continue;
          }
          const name = sanitizeName(rawName);
          if (!name) {
            skipped.push(`(empty after sanitize): ${rawName}`);
            continue;
          }
          const a = addrArg(addr);
          try {
            await h.cmd(`f ${name} @ ${a}`);
            if (e.kind === "function") {
              await h.cmd(`af ${name} @ ${a}`);
              await h.cmd(`afn ${name} @ ${a}`);
              functions++;
            }
            imported++;
          } catch (err) {
            skipped.push(`${name}@${a}: ${String(err)}`);
          }
        }

        const lines = [
          `imported ${imported}/${entries.length} symbol(s) into "${target}" (${functions} as functions).`,
        ];
        if (skipped.length) {
          lines.push(`skipped ${skipped.length}:`);
          lines.push(...skipped.slice(0, 20));
          if (skipped.length > 20) lines.push(`…(+${skipped.length - 20} more)`);
        }
        lines.push("Call save_project to persist these names.");
        return capped(lines.join("\n"));
      })
  );
}
