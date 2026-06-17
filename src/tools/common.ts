/**
 * tools/common.ts — shared building blocks for every tool module.
 *
 * Keeps the per-tool files tiny and consistent: the MCP result wrappers, the
 * error `guard`, a Thumb-region hint helper, and a couple of compact JSON
 * formatters. All real output still funnels through capOutput (util.ts).
 */

import type { R2Handle } from "../sessions.js";
import { capOutput, errMsg, resolveAddr } from "../util.js";

/** Standard MCP text result. */
export function text(s: string) {
  return { content: [{ type: "text" as const, text: s }] };
}

/** Standard MCP error result (isError so the client surfaces it, but never a raw throw). */
export function fail(s: string) {
  return { content: [{ type: "text" as const, text: s }], isError: true };
}

/** Run an async tool body, converting any thrown error into a clean MCP error result. */
export async function guard(fn: () => Promise<any>) {
  try {
    return await fn();
  } catch (e) {
    return fail(`error: ${errMsg(e)}`);
  }
}

/** Convenience: cap + wrap in a text result. */
export function capped(s: string, opts?: { maxLines?: number; maxChars?: number }) {
  return text(capOutput(s, opts));
}

/** Format a possibly-number address field as canonical 0x hex. */
export function hex(v: unknown): string {
  if (typeof v === "number") return "0x" + (v >>> 0).toString(16);
  if (typeof v === "string" && v !== "") return v;
  return "?";
}

/**
 * Best-effort Thumb-region hint over a function's extent. Many BCM67xx dongle
 * functions are Thumb-2; without `ahb 16` over the region r2 decodes ARM-32
 * garbage. We apply `e asm.bits=16` + `ahb 16` across [addr, addr+size) when the
 * caller indicates Thumb, then leave it set (idempotent, harmless to re-apply).
 *
 * LIMITATION: r2 has no single command to apply a hint over a byte range, so we
 * set asm.bits and place a hint at the entry. For mixed ARM/Thumb functions this
 * may still mis-decode a tail; use thumb_disasm on a specific sub-address if so.
 */
export async function applyThumbHint(
  handle: R2Handle,
  addr: string,
  size?: number
): Promise<void> {
  await handle.cmd("e asm.bits=16");
  await handle.cmd(`ahb 16 @ ${addr}`);
  if (size && size > 0) {
    // Place an end-of-region hint too so the analyzer keeps bits=16 across it.
    await handle.cmd(`ahb 16 @ ${addr}+${size - 1}`);
  }
}

/** Resolve an addr-or-name argument; thin re-export so tool modules import one place. */
export { resolveAddr };

/**
 * Window an array of rows by `offset`/`limit` BEFORE formatting/capping, and
 * return the slice plus a footer describing the window. Keeps default behavior
 * intact: with no offset/limit the whole array passes through and footer="".
 *
 * The footer (when windowed) reads:
 *   [showing N..M of TOTAL — pass offset=M to continue]
 * so the caller can paginate the high-volume tools without flooding context.
 */
export function paginate<T>(
  rows: T[],
  offset?: number,
  limit?: number
): { slice: T[]; footer: string; start: number; end: number; total: number } {
  const total = rows.length;
  const start = Math.max(0, Math.floor(offset ?? 0));
  const end =
    limit !== undefined && limit !== null
      ? Math.min(total, start + Math.max(0, Math.floor(limit)))
      : total;
  const slice = rows.slice(start, end);
  const windowed = start > 0 || end < total;
  const footer = windowed
    ? `\n[showing ${start}..${end} of ${total}` +
      (end < total ? ` — pass offset=${end} to continue]` : "]")
    : "";
  return { slice, footer, start, end, total };
}

/**
 * Filter disasm text to only lines matching `pattern` (case-insensitive).
 * Treated as a regex; if the pattern is not a valid regex it falls back to a
 * plain (case-insensitive) substring match. Appends a footer
 * `[grep "<pat>": <kept>/<total> lines]`. Mirrors agents piping r2 output
 * through `grep -iE '…'`. Apply BEFORE capOutput.
 */
export function grepLines(text: string, pattern: string): string {
  const lines = text.split("\n");
  let test: (l: string) => boolean;
  try {
    const re = new RegExp(pattern, "i");
    test = (l) => re.test(l);
  } catch {
    const needle = pattern.toLowerCase();
    test = (l) => l.toLowerCase().includes(needle);
  }
  const kept = lines.filter(test);
  const footer = `\n[grep "${pattern}": ${kept.length}/${lines.length} lines]`;
  return kept.join("\n") + footer;
}

/** Detect whether the function/region at `addr` is Thumb per r2's analysis. */
export async function isThumbAt(handle: R2Handle, addr: string): Promise<boolean> {
  try {
    const j = await handle.cmdj(`afij @ ${addr}`);
    const info = Array.isArray(j) ? j[0] : j;
    if (info && typeof info.bits === "number") return info.bits === 16;
  } catch {
    /* fall through */
  }
  // Fallback: query the asm.bits hint at this address.
  try {
    const b = (await handle.cmd(`ahb @ ${addr}`)).trim();
    if (/16/.test(b)) return true;
  } catch {
    /* ignore */
  }
  return false;
}
