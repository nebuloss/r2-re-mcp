/**
 * sessions.ts — persistent r2pipe session management.
 *
 * The stock r2mcp is stateless, so each call re-opens/re-analyzes the binary
 * (slow, and analysis state is lost). Here we keep ONE persistent r2pipe handle
 * per opened target, keyed by a friendly `name`, reused across every tool call.
 * Flags/comments/analysis accumulate in-process and can be persisted with the
 * r2 project commands (Ps/Po) — see tools.ts save_project / open_target.
 *
 * ADDRESSING NOTE (bake-in): in r2 the addresses ARE the firmware virtual
 * address directly. For the raw dongle blob `ram.shift.bin` the load base is 0,
 * so r2-addr == firmware-VA (e.g. iDMA gate setter at 0xf335c). This is UNLIKE
 * the team's Ghidra setup, which carries a +0x10000 image-base skew. Do NOT
 * apply any 0x10000 offset here.
 */

import { createRequire } from "node:module";
import * as path from "node:path";
import * as fs from "node:fs";
import { log, errMsg } from "./util.js";

// r2pipe ships a malformed r2pipe.d.ts (invalid param syntax that triggers TS1005,
// which skipLibCheck does NOT suppress — that only skips semantic checks). Import it
// untyped via createRequire so tsc never parses those broken type declarations.
const require = createRequire(import.meta.url);
const r2pipe: any = require("r2pipe");

export const RE_BINS = process.env.RE_BINS ?? "/opt/re-bins";
export const R2_PROJECT_DIR =
  process.env.R2_PROJECT_DIR ?? path.join(RE_BINS, ".r2projects");

/** A thin async wrapper around the callback-style r2pipe handle. */
export interface R2Handle {
  cmd(command: string): Promise<string>;
  cmdj(command: string): Promise<any>;
  quit(): Promise<void>;
}

interface Session {
  name: string;
  filePath: string;
  arch: string;
  bits: number;
  baseAddr: number;
  handle: R2Handle;
}

/** Promisify the r2pipe callback handle returned by r2pipe.open(). */
function wrap(raw: any): R2Handle {
  return {
    cmd(command: string): Promise<string> {
      return new Promise((resolve, reject) => {
        raw.cmd(command, (err: any, res: string) => {
          if (err) reject(err);
          else resolve(res ?? "");
        });
      });
    },
    cmdj(command: string): Promise<any> {
      return new Promise((resolve, reject) => {
        raw.cmdj(command, (err: any, res: any) => {
          if (err) reject(err);
          else resolve(res);
        });
      });
    },
    quit(): Promise<void> {
      return new Promise((resolve) => {
        try {
          raw.quit(() => resolve());
        } catch {
          resolve();
        }
      });
    },
  };
}

export type AnalysisDepth = "none" | "basic" | "full";

export interface OpenOpts {
  arch?: string; // default "arm"
  bits?: number; // default 32
  baseAddr?: number; // default 0
  analysis?: AnalysisDepth; // default "basic" (aa); "full"=aaa; "none"=skip
}

export interface OpenSummary {
  name: string;
  file: string;
  size: number;
  arch: string;
  bits: number;
  base: string;
  functions: number;
  projectLoaded: boolean;
  reused: boolean;
}

export class SessionManager {
  private sessions = new Map<string, Session>();

  has(name: string): boolean {
    return this.sessions.has(name);
  }

  /** Get a live handle or throw a clean, actionable error. */
  get(name: string): R2Handle {
    const s = this.sessions.get(name);
    if (!s) {
      throw new Error(
        `target "${name}" is not open. Call open_target({ name: "${name}" }) first.`
      );
    }
    return s.handle;
  }

  list(): { name: string; file: string; arch: string; bits: number }[] {
    return [...this.sessions.values()].map((s) => ({
      name: s.name,
      file: s.filePath,
      arch: s.arch,
      bits: s.bits,
    }));
  }

  /**
   * Open a staged binary into a persistent session. If `name` is already open
   * the existing session is reused (reused=true) and no re-analysis happens.
   *
   * Resolution: if `name` is an absolute/existing path it is used directly,
   * otherwise it is resolved under RE_BINS (so callers pass "ram.shift.bin").
   *
   * Light analysis only (`aa`) to keep open fast; deeper analysis is available
   * on demand via r2cmd({ cmd: "aaa" }).
   */
  async open(name: string, opts: OpenOpts = {}): Promise<OpenSummary> {
    const arch = opts.arch ?? "arm";
    const bits = opts.bits ?? 32;
    const baseAddr = opts.baseAddr ?? 0;
    const analysis: AnalysisDepth = opts.analysis ?? "basic";

    if (this.sessions.has(name)) {
      const s = this.sessions.get(name)!;
      const funcs = await this.functionCount(s.handle);
      return {
        name: s.name,
        file: s.filePath,
        size: this.fileSize(s.filePath),
        arch: s.arch,
        bits: s.bits,
        base: "0x" + s.baseAddr.toString(16),
        functions: funcs,
        projectLoaded: false,
        reused: true,
      };
    }

    const filePath = this.resolvePath(name);
    if (!fs.existsSync(filePath)) {
      throw new Error(
        `binary not found: ${filePath} (RE_BINS=${RE_BINS}). Stage it on the container first.`
      );
    }

    // r2pipe.open flags: raw arch/bits + map base. The blob loads at baseAddr
    // (0 for ram.shift.bin, so r2-addr == firmware-VA). -b is bits, -a is arch,
    // -m sets the map address (only when non-zero to avoid surprises).
    const flags = ["-a", arch, "-b", String(bits)];
    if (baseAddr !== 0) flags.push("-m", "0x" + baseAddr.toString(16));

    log.info(`opening "${name}" -> ${filePath} (arch=${arch} bits=${bits} base=0x${baseAddr.toString(16)})`);

    const raw = await new Promise<any>((resolve, reject) => {
      r2pipe.open(filePath, flags, (err: any, r2: any) => {
        if (err) reject(err);
        else resolve(r2);
      });
    });
    const handle = wrap(raw);

    // Analysis depth (default "basic"=aa). xref/function tools need at least
    // basic, ideally "full" (aaa). "none" skips entirely (fast open, but the
    // function/xref tools will be empty until analyze() is called).
    if (analysis !== "none") {
      const cmd = analysis === "full" ? "aaa" : "aa";
      try {
        await handle.cmd(cmd);
      } catch (e) {
        log.warn(`${cmd} failed for ${name}: ${errMsg(e)}`);
      }
    }

    // Auto-load matching r2 project if one exists (Po <name>).
    let projectLoaded = false;
    try {
      const projFile = path.join(R2_PROJECT_DIR, name);
      if (fs.existsSync(projFile) || fs.existsSync(projFile + ".rzdb") || fs.existsSync(projFile + ".r2")) {
        await handle.cmd(`e prj.dir=${R2_PROJECT_DIR}`);
        const res = await handle.cmd(`Po ${name}`);
        projectLoaded = !/Cannot|No such|error/i.test(res);
        log.info(`project load (Po ${name}) -> ${projectLoaded ? "ok" : "noop"}`);
      }
    } catch (e) {
      log.warn(`project auto-load failed for ${name}: ${errMsg(e)}`);
    }

    const session: Session = { name, filePath, arch, bits, baseAddr, handle };
    this.sessions.set(name, session);

    const functions = await this.functionCount(handle);
    return {
      name,
      file: filePath,
      size: this.fileSize(filePath),
      arch,
      bits,
      base: "0x" + baseAddr.toString(16),
      functions,
      projectLoaded,
      reused: false,
    };
  }

  async close(name: string): Promise<boolean> {
    const s = this.sessions.get(name);
    if (!s) return false;
    try {
      await s.handle.quit();
    } catch (e) {
      log.warn(`error closing ${name}: ${errMsg(e)}`);
    }
    this.sessions.delete(name);
    return true;
  }

  /** Graceful shutdown — close every handle. Wired to SIGINT/SIGTERM in server.ts. */
  async closeAll(): Promise<void> {
    const names = [...this.sessions.keys()];
    log.info(`closing ${names.length} session(s): ${names.join(", ")}`);
    await Promise.all(names.map((n) => this.close(n)));
  }

  private resolvePath(name: string): string {
    if (path.isAbsolute(name) && fs.existsSync(name)) return name;
    if (name.includes("/") && fs.existsSync(name)) return path.resolve(name);
    return path.join(RE_BINS, name);
  }

  private fileSize(p: string): number {
    try {
      return fs.statSync(p).size;
    } catch {
      return -1;
    }
  }

  private async functionCount(handle: R2Handle): Promise<number> {
    try {
      const j = await handle.cmdj("aflj");
      return Array.isArray(j) ? j.length : 0;
    } catch {
      return 0;
    }
  }
}
