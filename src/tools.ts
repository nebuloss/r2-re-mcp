/**
 * tools.ts — the lean, recipe-encoded, output-capped MCP toolset.
 *
 * Design rules (enforced here):
 *   - STATEFUL: every tool operates on a persistent session via SessionManager.
 *   - TOKEN-DISCIPLINED: every text result goes through capOutput().
 *   - RECIPE-ENCODED: the team's r2 recipes are baked in (esp. Thumb-2 + addr facts).
 *
 * CRITICAL ADDRESSING / RECIPE FACTS (do not "fix" these):
 *   - Addresses are the firmware virtual address DIRECTLY. No +0x10000 skew
 *     (that skew only exists in the team's Ghidra project, not here).
 *   - THUMB-2 disassembly requires the full recipe, NOT just `e asm.bits=16`:
 *         e asm.bits=16 ; ahb 16 @ ADDR ; pd N @ ADDR
 *     The `ahb 16 @ADDR` (analysis hint: bits=16) is MANDATORY or r2 will
 *     decode ARM-32 garbage at a Thumb address.
 *   - Reference targets in ram.shift.bin: hme_sys_g=0xeb700, per-user gate u16
 *     at 0xebb2c, iDMA gate setter fn at 0xf335c.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  SessionManager,
  type R2Handle,
} from "./sessions.js";
import { capOutput, addrArg, errMsg, log } from "./util.js";
import { text, fail, guard, paginate, grepLines } from "./tools/common.js";
import { registerAnalysisTools } from "./tools/analysis.js";
import { registerTriageTools } from "./tools/triage.js";
import { registerFunctionTools } from "./tools/functions.js";
import { registerCallgraphTools } from "./tools/callgraph.js";
import { registerEmulateTools } from "./tools/emulate.js";
import { registerSymbolTools } from "./tools/symbols.js";
import { registerTypeTools } from "./tools/types.js";
import { registerDiffTools } from "./tools/diff.js";

/**
 * Probe which decompiler commands are available in this r2 build, in order of
 * preference: r2ghidra (pdg) > r2dec (pdd) > builtin pseudo-decompiler (pdc).
 * Cached per process. We probe by listing loaded plugins / cmd descriptors.
 */
let decompilerProbe: Promise<"pdg" | "pdd" | "pdc"> | null = null;
async function pickDecompiler(handle: R2Handle): Promise<"pdg" | "pdd" | "pdc"> {
  if (!decompilerProbe) {
    decompilerProbe = (async () => {
      try {
        const cmds = await handle.cmd("e cmd.??~pd; pd?"); // best-effort
        // More reliable: check loaded core plugins.
        const plugins = (await handle.cmd("Lc")) + " " + (await handle.cmd("L")).slice(0, 4000);
        if (/pdg/.test(plugins) || /ghidra/i.test(plugins)) return "pdg";
        if (/pdd/.test(plugins) || /r2dec/i.test(plugins)) return "pdd";
        void cmds;
      } catch (e) {
        log.warn(`decompiler probe failed: ${errMsg(e)}`);
      }
      return "pdc"; // builtin pseudo-decompiler is always present
    })();
  }
  return decompilerProbe;
}

/** Format an axtj/axfj JSON xref list compactly, capped at `limit` entries. */
function formatXrefs(
  rows: any[],
  direction: "to" | "from",
  limit = 100
): string {
  if (!Array.isArray(rows) || rows.length === 0) {
    return `(no xrefs ${direction})`;
  }
  const total = rows.length;
  const shown = rows.slice(0, limit);
  const lines = shown.map((r) => {
    const from = r.from ?? r.fromaddr ?? r.addr;
    const to = r.to ?? r.toaddr ?? r.ref;
    const type = r.type ?? "?";
    const fcn = r.fcn_name ?? r.fcn ?? r.realname ?? "";
    const op = (r.opcode ?? r.disasm ?? "").toString().trim();
    const fa = typeof from === "number" ? "0x" + from.toString(16) : String(from ?? "?");
    const ta = typeof to === "number" ? "0x" + to.toString(16) : String(to ?? "?");
    const site = direction === "to" ? fa : ta;
    const parts = [`${site}`, `[${type}]`];
    if (fcn) parts.push(`in ${fcn}`);
    if (op) parts.push(`: ${op}`);
    return parts.join(" ");
  });
  let header = `${total} xref(s) ${direction}`;
  if (total > limit) header += ` (showing first ${limit})`;
  return header + ":\n" + lines.join("\n");
}

/** Build the optional tmp-arch suffix for a `pd` command (VALIDATED: `@a:arm:64`). */
function archSuffix(arch?: string, bits?: number): string {
  return arch && bits ? ` @a:${arch}:${bits}` : "";
}

export function registerTools(server: McpServer, sm: SessionManager): void {
  // ---------------------------------------------------------------------------
  // 1. open_target — open/reuse a persistent session, light-analyze, auto-load project.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "open_target",
    {
      title: "Open target binary",
      description:
        "Open a staged binary from RE_BINS into a persistent r2 session keyed by `name` " +
        "(reused if already open). `analysis` controls depth: 'none' (fast, no functions/xrefs) " +
        "| 'basic'=aa (default) | 'full'=aaa. The xref/function/callgraph tools need at least " +
        "'basic', ideally 'full' — or call analyze() afterward. Auto-loads a matching r2 project " +
        "if present. Addresses are firmware-VA directly (NO +0x10000 skew). Defaults: arch=arm bits=32 base=0.",
      inputSchema: {
        name: z
          .string()
          .describe("Binary name under RE_BINS (e.g. 'ram.shift.bin') or an absolute path."),
        arch: z.string().optional().describe("r2 arch, default 'arm'."),
        bits: z.number().int().optional().describe("Bits, default 32 (Thumb is set per-region via ahb)."),
        baseAddr: z.number().int().optional().describe("Load/map base, default 0 (ram.shift.bin: r2-addr==FW-VA)."),
        analysis: z
          .enum(["none", "basic", "full"])
          .optional()
          .describe("Analysis depth at open: 'none' | 'basic'=aa (default) | 'full'=aaa."),
      },
    },
    async ({ name, arch, bits, baseAddr, analysis }) =>
      guard(async () => {
        const s = await sm.open(name, { arch, bits, baseAddr, analysis });
        const out =
          `target "${s.name}" ${s.reused ? "(reused existing session)" : "opened"}\n` +
          `  file:      ${s.file}\n` +
          `  size:      ${s.size} bytes\n` +
          `  arch/bits: ${s.arch}/${s.bits}\n` +
          `  base:      ${s.base}\n` +
          `  functions: ${s.functions}\n` +
          `  project:   ${s.projectLoaded ? "loaded (P, sanitized name)" : "none"}` +
          (s.analysisFromProject ? "\n  analysis:  recovered from project (skipped aa/aaa)" : "");
        return text(capOutput(out));
      })
  );

  // ---------------------------------------------------------------------------
  // 2. thumb_disasm — the mandatory Thumb-2 recipe.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "thumb_disasm",
    {
      title: "Disassemble (Thumb-2)",
      description:
        "Disassemble Thumb-2 at `addr` using the REQUIRED recipe: " +
        "`e asm.bits=16; ahb 16 @addr; pd n @addr`. The ahb hint is mandatory — " +
        "`e asm.bits=16` alone decodes ARM-32 garbage. Use for the iDMA gate fn @0xf335c.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA (e.g. 0xf335c or 'sym.foo')."),
        n: z.number().int().optional().describe("Instruction count, default 32."),
      },
    },
    async ({ target, addr, n }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = addrArg(addr);
        const count = n ?? 32;
        await h.cmd("e asm.bits=16");
        await h.cmd(`ahb 16 @ ${a}`);
        const out = await h.cmd(`pd ${count} @ ${a}`);
        return text(capOutput(out));
      })
  );

  // ---------------------------------------------------------------------------
  // 3. disasm — plain ARM disasm.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "disasm",
    {
      title: "Disassemble (ARM)",
      description:
        "ARM disassembly: `pd n @addr`. For Thumb code use thumb_disasm instead. " +
        "Supports offset/limit pagination (windows the disasm lines). " +
        "Optional per-call `arch`+`bits` override (BOTH required) appends `@a:<arch>:<bits>` — " +
        "the clean per-call alternative to thumb_disasm's global `ahb` (e.g. arch='arm',bits=16 " +
        "for Thumb; bits=64 for aarch64 targets like dhd.ko). Optional `grep` filters output " +
        "lines (case-insensitive regex, substring fallback) before capping.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
        n: z.number().int().optional().describe("Instruction count, default 32."),
        arch: z.string().optional().describe("Per-call arch override (use WITH bits), e.g. 'arm'."),
        bits: z.number().int().optional().describe("Per-call bits override (use WITH arch): 16=Thumb, 64=aarch64."),
        grep: z.string().optional().describe("Filter output to matching lines (case-insensitive regex; substring fallback)."),
        offset: z.number().int().optional().describe("Pagination start line (default 0)."),
        limit: z.number().int().optional().describe("Max disasm lines to return from offset."),
      },
    },
    async ({ target, addr, n, arch, bits, grep, offset, limit }) =>
      guard(async () => {
        const h = sm.get(target);
        let out = await h.cmd(`pd ${n ?? 32} @ ${addrArg(addr)}${archSuffix(arch, bits)}`);
        if (grep) out = grepLines(out, grep);
        if (offset !== undefined || limit !== undefined) {
          const { slice, footer } = paginate(out.split("\n"), offset, limit);
          return text(capOutput(slice.join("\n") + footer));
        }
        return text(capOutput(out));
      })
  );

  // ---------------------------------------------------------------------------
  // 3b. disasm_batch — disassemble several regions in ONE call (token saver).
  // ---------------------------------------------------------------------------
  server.registerTool(
    "disasm_batch",
    {
      title: "Disassemble multiple regions",
      description:
        "Disassemble several regions in ONE call. Each region: `addr` (+ optional `n` default 24, " +
        "per-region `arch`+`bits` override appending `@a:<arch>:<bits>`, and a `label`). Each block " +
        "is prefixed with a `=== <label|addr> ===` marker, then the whole thing is capped. " +
        "Optional top-level `grep` filters the combined output (case-insensitive regex; substring " +
        "fallback). Mirrors the agent pattern of disassembling several regions with marker separators. " +
        "Max 20 regions.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        regions: z
          .array(
            z.object({
              addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
              n: z.number().int().optional().describe("Instruction count, default 24."),
              arch: z.string().optional().describe("Per-region arch override (use WITH bits)."),
              bits: z.number().int().optional().describe("Per-region bits override (use WITH arch)."),
              label: z.string().optional().describe("Marker header label (defaults to the addr)."),
            })
          )
          .describe("Regions to disassemble (max 20)."),
        grep: z.string().optional().describe("Filter combined output to matching lines (case-insensitive regex; substring fallback)."),
      },
    },
    async ({ target, regions, grep }) =>
      guard(async () => {
        const h = sm.get(target);
        if (!Array.isArray(regions) || regions.length === 0) {
          return fail("disasm_batch: provide a non-empty `regions` array.");
        }
        const capped20 = regions.slice(0, 20);
        const blocks: string[] = [];
        for (const r of capped20) {
          const a = addrArg(r.addr);
          const header = `=== ${r.label ?? a} ===`;
          const body = await h.cmd(`pd ${r.n ?? 24} @ ${a}${archSuffix(r.arch, r.bits)}`);
          blocks.push(`${header}\n${body}`);
        }
        let out = blocks.join("\n");
        if (regions.length > 20) out += `\n[disasm_batch: capped to first 20 of ${regions.length} regions]`;
        if (grep) out = grepLines(out, grep);
        return text(capOutput(out));
      })
  );

  // ---------------------------------------------------------------------------
  // 4. decompile — pdg/pdd/pdc with graceful fallback.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "decompile",
    {
      title: "Decompile function",
      description:
        "Decompile the function containing `addr`. Probes for r2ghidra (pdg) > r2dec (pdd) > " +
        "builtin pseudo-decompiler (pdc) and uses the best available. Output capped.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol within the function."),
      },
    },
    async ({ target, addr }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = addrArg(addr);
        const cmd = await pickDecompiler(h);
        let out = "";
        try {
          out = await h.cmd(`${cmd} @ ${a}`);
        } catch (e) {
          log.warn(`${cmd} failed, falling back to pdc: ${errMsg(e)}`);
        }
        if (!out || !out.trim()) {
          out = await h.cmd(`pdc @ ${a}`);
        }
        if (!out || !out.trim()) {
          out = `(no decompiler output at ${a}; tried ${cmd}/pdc — ensure the function is analyzed, e.g. r2cmd('af @ ${a}'))`;
        }
        return text(capOutput(`# decompiler: ${cmd}\n` + out));
      })
  );

  // ---------------------------------------------------------------------------
  // 5. xrefs_to / 6. xrefs_from — trimmed JSON xref lists.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "xrefs_to",
    {
      title: "Xrefs to address",
      description:
        "References pointing TO `addr` (axtj). Trimmed list: site addr, type, containing " +
        "function, one-line disasm. Capped at 100. Good for: who writes the gate u16 @0xebb2c.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
      },
    },
    async ({ target, addr }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = addrArg(addr);
        let rows: any[] = [];
        try {
          rows = (await h.cmdj(`axtj @ ${a}`)) ?? [];
        } catch (e) {
          log.warn(`axtj failed, falling back to axt: ${errMsg(e)}`);
          return text(capOutput(await h.cmd(`axt @ ${a}`)));
        }
        return text(capOutput(formatXrefs(rows, "to")));
      })
  );

  server.registerTool(
    "xrefs_from",
    {
      title: "Xrefs from address",
      description:
        "References originating FROM `addr` (axfj). Trimmed list: target addr, type, " +
        "containing function, one-line disasm. Capped at 100.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
      },
    },
    async ({ target, addr }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = addrArg(addr);
        let rows: any[] = [];
        try {
          rows = (await h.cmdj(`axfj @ ${a}`)) ?? [];
        } catch (e) {
          log.warn(`axfj failed, falling back to axf: ${errMsg(e)}`);
          return text(capOutput(await h.cmd(`axf @ ${a}`)));
        }
        return text(capOutput(formatXrefs(rows, "from")));
      })
  );

  // ---------------------------------------------------------------------------
  // 7. read_mem — compact hexdump.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "read_mem",
    {
      title: "Read memory (hexdump)",
      description:
        "Compact hexdump of `len` bytes at `addr` (default 64). Good for struct fields, " +
        "e.g. read the per-user gate at hme_sys_g+0x42c (=0xebb2c). Output capped.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
        len: z.number().int().optional().describe("Byte count, default 64."),
      },
    },
    async ({ target, addr, len }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = addrArg(addr);
        const n = len ?? 64;
        // px gives a labelled, compact hexdump that reads well in-context.
        const out = await h.cmd(`px ${n} @ ${a}`);
        return text(capOutput(out));
      })
  );

  // ---------------------------------------------------------------------------
  // 8. search — bytes / string / value.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "search",
    {
      title: "Search binary",
      description:
        "Search the binary. kind='bytes' (/x hex pairs e.g. '5c33'), kind='string' (/ plain " +
        "text), kind='value' (/v numeric value). Returns a capped hit list (addr + context).",
      inputSchema: {
        target: z.string().describe("Open session name."),
        query: z.string().describe("Hex byte string, text, or numeric value depending on kind."),
        kind: z.enum(["bytes", "string", "value"]).optional().describe("Search kind, default 'string'."),
        offset: z.number().int().optional().describe("Pagination start index over hits (default 0)."),
        limit: z.number().int().optional().describe("Max hits to return from offset."),
      },
    },
    async ({ target, query, kind, offset, limit }) =>
      guard(async () => {
        const h = sm.get(target);
        const k = kind ?? "string";
        let cmd: string;
        if (k === "bytes") cmd = `/x ${query.replace(/\s+/g, "")}`;
        else if (k === "value") cmd = `/v ${query}`;
        else cmd = `/ ${query}`;
        const out = await h.cmd(cmd);
        if (!out || !out.trim()) {
          return text(capOutput(`(no hits for ${k} search: ${query})`));
        }
        if (offset !== undefined || limit !== undefined) {
          const hits = out.split("\n").filter((l) => l.trim() !== "");
          const { slice, footer } = paginate(hits, offset, limit);
          return text(capOutput(slice.join("\n") + footer));
        }
        return text(capOutput(out));
      })
  );

  // ---------------------------------------------------------------------------
  // 9. r2cmd — guarded escape hatch / power tool.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "r2cmd",
    {
      title: "Raw r2 command (escape hatch)",
      description:
        "ESCAPE VALVE: run an arbitrary r2 command on the session for cases the recipes don't " +
        "cover (e.g. 'aaa' for deep analysis, 'afl' to list functions, 'is' for symbols). " +
        "Output is capped like every other tool — do not expect raw megadumps.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        cmd: z.string().describe("Raw r2 command string (e.g. 'aaa', 'afl', 'pdf @ 0xf335c')."),
      },
    },
    async ({ target, cmd }) =>
      guard(async () => {
        const h = sm.get(target);
        const out = await h.cmd(cmd);
        return text(capOutput(out && out.trim() ? out : "(command produced no output)"));
      })
  );

  // ---------------------------------------------------------------------------
  // 10. save_project — persist flags/comments/analysis (Ps). Loading is automatic.
  // ---------------------------------------------------------------------------
  server.registerTool(
    "save_project",
    {
      title: "Save r2 project",
      description:
        "Persist flags/comments/analysis to disk via r2 project (`Ps <name>` into R2_PROJECT_DIR). " +
        "Loading is automatic in open_target. Call this after annotate() to make changes durable.",
      inputSchema: {
        target: z.string().describe("Open session name (also used as the project name)."),
      },
    },
    async ({ target }) =>
      guard(async () => {
        sm.get(target); // guard: clean error if not open
        const r = await sm.saveProject(target);
        const note = r.ok ? "" : ` (best-effort: r2 said: ${r.note})`;
        return text(capOutput(`saved project "${target}" -> ${r.where}${note}`));
      })
  );

  // ---------------------------------------------------------------------------
  // 11. annotate — set flag and/or comment (durable only after save_project).
  // ---------------------------------------------------------------------------
  server.registerTool(
    "annotate",
    {
      title: "Annotate (flag/comment)",
      description:
        "Set a flag (`f <flag> @addr`) and/or a comment (`CCu <comment> @addr`) at `addr`. " +
        "NOTE: these live in-session and persist to disk ONLY after you call save_project.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z.union([z.string(), z.number()]).describe("Firmware-VA or symbol."),
        flag: z.string().optional().describe("Flag name to set at addr (e.g. 'fn.idma_gate_set')."),
        comment: z.string().optional().describe("Comment text to attach at addr."),
      },
    },
    async ({ target, addr, flag, comment }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = addrArg(addr);
        if (!flag && !comment) {
          return fail("annotate: provide at least one of `flag` or `comment`.");
        }
        const done: string[] = [];
        if (flag) {
          await h.cmd(`f ${flag} @ ${a}`);
          done.push(`flag '${flag}'`);
        }
        if (comment) {
          // base64-encode via CCu? CCu sets a user comment; escape newlines.
          const safe = comment.replace(/\n/g, " ");
          await h.cmd(`CCu ${safe} @ ${a}`);
          done.push(`comment`);
        }
        return text(
          capOutput(`annotated ${a}: ${done.join(" + ")} (call save_project to persist).`)
        );
      })
  );

  // ---------------------------------------------------------------------------
  // v2 tool groups (registered from their own modules to keep this file lean):
  //   analysis.ts   — analyze, close_target
  //   triage.ts     — info, sections, list_symbols, strings
  //   functions.ts  — list_functions, function_info, disasm_function, rename
  //   callgraph.ts  — callers, callees
  //   emulate.ts    — emulate
  // ---------------------------------------------------------------------------
  registerAnalysisTools(server, sm);
  registerTriageTools(server, sm);
  registerFunctionTools(server, sm);
  registerCallgraphTools(server, sm);
  registerEmulateTools(server, sm);
  registerSymbolTools(server, sm);
  registerTypeTools(server, sm);
  registerDiffTools(server, sm);
}
