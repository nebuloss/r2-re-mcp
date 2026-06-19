/**
 * tools/firmware.ts — firmware-blob triage that isn't r2-session based.
 *
 * binwalk signature-scans a staged blob (e.g. rtecdc.bin) for embedded
 * filesystems / compression / structures / strings, and can carve them out.
 * Complements open_target+disasm (which treats the blob as raw code).
 */

import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs";
import { execFile } from "node:child_process";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager } from "../sessions.js";
import { RE_BINS } from "../sessions.js";
import { guard, capped } from "./common.js";

const RE_WORK = process.env.RE_WORK ?? "/opt/re-work";

function resolveFile(name: string): string {
  if (path.isAbsolute(name) && fs.existsSync(name)) return name;
  const p = path.join(RE_BINS, name);
  if (!fs.existsSync(p)) throw new Error(`file not found: ${p} (RE_BINS=${RE_BINS})`);
  return p;
}

function run(cmd: string, args: string[], cwd?: string, timeoutMs = 120_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { cwd, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      const out = (stdout || "") + (stderr ? "\n[stderr] " + stderr : "");
      if (err && !out.trim()) reject(new Error((err.message || "exec failed").slice(0, 300)));
      else resolve(out);
    });
  });
}

export function registerFirmwareTools(server: McpServer, _sm: SessionManager): void {
  server.registerTool(
    "binwalk",
    {
      title: "binwalk firmware scan",
      description:
        "Signature-scan a staged firmware blob (in RE_BINS) for embedded filesystems / compression / " +
        "structures / strings via binwalk. Set extract:true to carve embedded files out into RE_WORK " +
        "(binwalk -e). For raw ARM/Thumb firmware code, also use open_target + disasm.",
      inputSchema: {
        file: z.string().describe("Blob name under RE_BINS (or absolute path), e.g. rtecdc.bin."),
        extract: z
          .boolean()
          .optional()
          .describe("Carve out embedded files (binwalk -e) into RE_WORK. Default false (scan only)."),
      },
    },
    async ({ file, extract }) =>
      guard(async () => {
        const f = resolveFile(file);
        if (extract) {
          fs.mkdirSync(RE_WORK, { recursive: true });
          const out = await run("binwalk", ["-e", f], RE_WORK, 180_000);
          return capped(`binwalk -e ${f} (carved into ${RE_WORK})\n${out}`);
        }
        return capped(await run("binwalk", [f]));
      })
  );
}
