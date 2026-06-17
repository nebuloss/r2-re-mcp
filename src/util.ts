/**
 * util.ts — shared helpers for the r2-re-mcp server.
 *
 * The single most important thing in this file is `capOutput`: EVERY tool
 * funnels its result through it so the agent never gets a raw megadump that
 * floods the context window. That token-discipline is the whole reason this
 * server exists (the stock r2mcp returns unbounded text, so agents bypass it).
 */

/** Default output caps. Applied by every tool unless it asks for tighter ones. */
export const DEFAULT_MAX_LINES = 200;
export const DEFAULT_MAX_CHARS = 4000;

export interface CapOpts {
  maxLines?: number;
  maxChars?: number;
}

/**
 * Cap a block of text to at most `maxLines` lines AND `maxChars` characters,
 * appending a clear "…[truncated N lines]" / "…[truncated to N chars]" marker
 * so the caller knows output was elided and can request a narrower window.
 *
 * Line-cap is applied first, then the char-cap on whatever survives.
 */
export function capOutput(text: string, opts: CapOpts = {}): string {
  const maxLines = opts.maxLines ?? DEFAULT_MAX_LINES;
  const maxChars = opts.maxChars ?? DEFAULT_MAX_CHARS;

  if (text === undefined || text === null) return "";
  let out = String(text);

  // --- line cap ---
  const lines = out.split("\n");
  let lineNote = "";
  if (lines.length > maxLines) {
    const dropped = lines.length - maxLines;
    out = lines.slice(0, maxLines).join("\n");
    lineNote = `\n…[truncated ${dropped} line${dropped === 1 ? "" : "s"}]`;
  }

  // --- char cap (on the post-line-cap text, marker excluded from the budget) ---
  let charNote = "";
  if (out.length > maxChars) {
    const dropped = out.length - maxChars;
    out = out.slice(0, maxChars);
    charNote = `\n…[truncated to ${maxChars} chars, ${dropped} more]`;
  }

  return out + lineNote + charNote;
}

/**
 * Normalize an address-ish argument into a string r2 will accept at `@`.
 * Accepts numbers, "0x..." strings, decimal strings, or symbol/flag names
 * (passed through verbatim so callers can use flags like `sym.foo`).
 */
export function addrArg(addr: string | number): string {
  if (typeof addr === "number") return "0x" + addr.toString(16);
  return addr.trim();
}

/** Minimal leveled logger to STDERR only (stdout must stay clean for the transport). */
type Level = "error" | "warn" | "info" | "debug";
const LEVELS: Record<Level, number> = { error: 0, warn: 1, info: 2, debug: 3 };

function currentLevel(): number {
  const env = (process.env.LOG_LEVEL ?? "info").toLowerCase() as Level;
  return LEVELS[env] ?? LEVELS.info;
}

function emit(level: Level, ...args: unknown[]): void {
  if (LEVELS[level] <= currentLevel()) {
    const ts = new Date().toISOString();
    // eslint-disable-next-line no-console
    console.error(`[${ts}] [${level.toUpperCase()}] [r2-re-mcp]`, ...args);
  }
}

export const log = {
  error: (...a: unknown[]) => emit("error", ...a),
  warn: (...a: unknown[]) => emit("warn", ...a),
  info: (...a: unknown[]) => emit("info", ...a),
  debug: (...a: unknown[]) => emit("debug", ...a),
};

/** Wrap an error into a clean, single-line string (never leak raw stack to the client). */
export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/**
 * Minimal structural view of an r2 handle, declared here to avoid a circular
 * import with sessions.ts (which imports from this file). Anything with cmd/cmdj
 * satisfies it (the real R2Handle does).
 */
interface CmdHandle {
  cmd(command: string): Promise<string>;
  cmdj(command: string): Promise<any>;
}

/** Looks like a numeric literal r2 can take verbatim at `@` (hex/dec). */
function looksNumeric(s: string): boolean {
  const t = s.trim();
  return /^[+-]?0x[0-9a-fA-F]+$/.test(t) || /^[+-]?[0-9]+$/.test(t);
}

/**
 * Resolve an "addr-or-name" argument to a concrete hex address string ("0x…").
 *
 * Strategy (cheap → richer), all best-effort:
 *   1. number / numeric-literal string → returned as canonical 0x hex.
 *   2. otherwise treat it as a symbol / flag / function name and ask r2 to
 *      evaluate it with `?vi <name>` (prints the decimal value of the
 *      expression, which for a known flag/symbol/function name is its address).
 *   3. fall back to a flag-table lookup (`f~ <name>`) and finally a function
 *      list match (`aflj`) by exact or suffix name.
 *
 * Throws a clean Error if nothing resolves, so callers get an actionable message
 * instead of r2 silently operating at the wrong (current seek) address.
 */
export async function resolveAddr(
  handle: CmdHandle,
  addr: string | number
): Promise<string> {
  if (typeof addr === "number") return "0x" + addr.toString(16);
  const raw = addr.trim();
  if (raw === "") throw new Error("empty address/name argument");
  if (looksNumeric(raw)) {
    // Normalize decimal → hex so downstream commands are consistent.
    const n = raw.startsWith("0x") || raw.startsWith("-0x") || raw.startsWith("+0x")
      ? parseInt(raw, 16)
      : parseInt(raw, 10);
    if (Number.isFinite(n)) return "0x" + (n >>> 0).toString(16);
    return raw;
  }

  // 2. Evaluate as an r2 expression / symbol name. `?vi` prints the integer
  //    value; an unknown name evaluates to 0, which we treat as "unresolved".
  try {
    const v = (await handle.cmd(`?vi ${raw}`)).trim();
    if (/^-?\d+$/.test(v)) {
      const n = parseInt(v, 10);
      if (n !== 0) return "0x" + (n >>> 0).toString(16);
    }
  } catch {
    /* fall through to flag/function lookup */
  }

  // 3a. Flag table: `f~name` lists matching flags as "<addr> <size> <name>".
  try {
    const ft = await handle.cmd(`f~${raw}`);
    for (const line of ft.split("\n")) {
      const m = line.trim().match(/^(0x[0-9a-fA-F]+)\s+\S+\s+(\S+)/);
      if (m && (m[2] === raw || m[2].endsWith(raw))) return m[1];
    }
  } catch {
    /* fall through */
  }

  // 3b. Function list match by exact or suffix name.
  try {
    const fns: any[] = (await handle.cmdj("aflj")) ?? [];
    const exact = fns.find((f) => f && (f.name === raw));
    const suffix = exact ?? fns.find((f) => f && typeof f.name === "string" && f.name.endsWith(raw));
    const sAddr = suffix?.addr ?? suffix?.offset;
    if (typeof sAddr === "number") {
      return "0x" + (sAddr >>> 0).toString(16);
    }
  } catch {
    /* fall through */
  }

  throw new Error(
    `could not resolve "${raw}" to an address (not a number, flag, symbol, or function name). ` +
      `Ensure the binary is analyzed (open_target analysis:"basic"/"full" or analyze()).`
  );
}
