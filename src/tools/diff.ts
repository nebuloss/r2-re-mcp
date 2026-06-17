/**
 * tools/diff.ts — cross-binary function diff (best-effort).
 *
 * `diff_functions` compares one function in target A against one in target B.
 * Two strategies, in order:
 *   1. If `radiff2` is on PATH, shell out to `radiff2 -AC <fileA> <fileB>` (full
 *      binary code diff) and surface the section mentioning the two functions.
 *   2. Otherwise (or if radiff2 fails) fall back to a normalized line-by-line
 *      disasm diff: fetch `pdf` from each open session, strip the address column
 *      and absolute operands (which differ trivially between builds), and diff
 *      the remaining mnemonic/operand stream.
 *
 * BEST-EFFORT: this is a coarse aid, not a semantic differ. Both targets must be
 * open first (open_target). Output is capped like every other tool.
 */

import { z } from "zod";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager, R2Handle } from "../sessions.js";
import { guard, capped, resolveAddr } from "./common.js";

const execFileP = promisify(execFile);

/** Is radiff2 available on PATH? Probed once per process. */
let radiff2Probe: Promise<boolean> | null = null;
function hasRadiff2(): Promise<boolean> {
  if (!radiff2Probe) {
    radiff2Probe = execFileP("radiff2", ["-v"])
      .then(() => true)
      .catch(() => false);
  }
  return radiff2Probe;
}

/**
 * Normalize a `pdf` disasm dump for build-to-build comparison:
 *  - drop everything up to and including the address column (`0x.... ` + bytes),
 *  - mask absolute hex literals (addresses/immediates) to `0x_`,
 *  - drop r2 comment/box-drawing decoration and blank lines.
 */
function normalizeDisasm(pdf: string): string[] {
  const out: string[] = [];
  for (const rawLine of pdf.split("\n")) {
    let l = rawLine;
    // strip leading box-drawing / gutter chars r2 prints in pdf.
    l = l.replace(/^[\s|`\\/:>-]+/, "");
    // strip "0xADDR <hexbytes>" prefix up to the mnemonic, if present.
    l = l.replace(/^0x[0-9a-fA-F]+\s+([0-9a-fA-F]{2,}\s+)?/, "");
    // drop trailing r2 comments.
    l = l.replace(/;.*$/, "");
    // mask absolute hex literals so trivial address skew doesn't show as diff.
    l = l.replace(/0x[0-9a-fA-F]+/g, "0x_");
    l = l.trim();
    if (l) out.push(l);
  }
  return out;
}

/** A minimal LCS-free, index-aligned diff that is good enough for a coarse view. */
function lineDiff(aLines: string[], bLines: string[], maxLines = 160): string[] {
  const max = Math.max(aLines.length, bLines.length);
  const diff: string[] = [];
  let same = 0;
  for (let i = 0; i < max && diff.length < maxLines; i++) {
    const a = aLines[i];
    const b = bLines[i];
    if (a === b) {
      same++;
      continue;
    }
    if (a !== undefined) diff.push(`- ${a}`);
    if (b !== undefined) diff.push(`+ ${b}`);
  }
  diff.unshift(`# ${same}/${max} lines identical (normalized); differences:`);
  return diff;
}

async function fnDisasm(h: R2Handle, fn: string | number): Promise<string> {
  const a = await resolveAddr(h, fn);
  return h.cmd(`pdf @ ${a}`);
}

export function registerDiffTools(server: McpServer, sm: SessionManager): void {
  server.registerTool(
    "diff_functions",
    {
      title: "Diff two functions (best-effort)",
      description:
        "BEST-EFFORT cross-binary diff of function `fnA` (in open target `targetA`) vs `fnB` (in open " +
        "target `targetB`). Uses `radiff2 -AC` over the two files if available, else a normalized " +
        "line-by-line disasm diff (addresses/immediates masked so trivial relocation skew is ignored). " +
        "Both targets must be open first (open_target). Coarse aid, not a semantic differ. Capped.",
      inputSchema: {
        targetA: z.string().describe("First open session name."),
        fnA: z.union([z.string(), z.number()]).describe("Function addr/name in targetA."),
        targetB: z.string().describe("Second open session name."),
        fnB: z.union([z.string(), z.number()]).describe("Function addr/name in targetB."),
      },
    },
    async ({ targetA, fnA, targetB, fnB }) =>
      guard(async () => {
        const ha = sm.get(targetA);
        const hb = sm.get(targetB);

        // Strategy 1: radiff2 over the two files (use the session's on-disk paths).
        if (await hasRadiff2()) {
          try {
            const pa = sm.filePathOf(targetA) ?? "";
            const pb = sm.filePathOf(targetB) ?? "";
            if (pa && pb) {
              const { stdout } = await execFileP("radiff2", ["-AC", pa, pb], {
                maxBuffer: 8 * 1024 * 1024,
              });
              const header =
                `# radiff2 -AC ${pa} ${pb}\n` +
                `# (best-effort whole-binary code diff; locate ${fnA} / ${fnB} below)\n`;
              return capped(header + (stdout && stdout.trim() ? stdout : "(no radiff2 output)"));
            }
          } catch {
            /* fall through to disasm diff */
          }
        }

        // Strategy 2: normalized disasm diff of the two functions.
        const [pa, pb] = await Promise.all([fnDisasm(ha, fnA), fnDisasm(hb, fnB)]);
        if ((!pa || !pa.trim()) && (!pb || !pb.trim())) {
          return capped(
            `(no disassembly for ${fnA}@${targetA} or ${fnB}@${targetB} — analyze both first)`
          );
        }
        const na = normalizeDisasm(pa);
        const nb = normalizeDisasm(pb);
        const header =
          `# normalized disasm diff (radiff2 unavailable/failed) — best-effort\n` +
          `# A: ${fnA} @ ${targetA} (${na.length} insn)  B: ${fnB} @ ${targetB} (${nb.length} insn)\n`;
        const body = lineDiff(na, nb);
        return capped(header + body.join("\n"));
      })
  );
}
