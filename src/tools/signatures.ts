/**
 * tools/signatures.ts — FLIRT-style function identification via r2 zignatures.
 *
 * De-anonymizes STRIPPED / ICF'd binaries (e.g. dhd.ko) by matching signatures
 * built from a KNOWN-symboled reference — typically the compiled open
 * brcmfmac/bcmdhd, or another symboled vendor build of the same code.
 *
 * Workflow:
 *   1. open + analyze(full) the symboled reference,  make_signatures -> file
 *   2. open + analyze the stripped target,            apply_signatures(file)
 *   3. list_functions on the target now shows recovered names.
 */

import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SessionManager, RE_BINS, projName } from "../sessions.js";
import { guard, text, capped } from "./common.js";

const SIG_DIR = path.join(RE_BINS, ".sigs");

export function registerSignatureTools(server: McpServer, sm: SessionManager): void {
  // make_signatures — generate zignatures from an analyzed, NAMED reference.
  server.registerTool(
    "make_signatures",
    {
      title: "Make FLIRT signatures",
      description:
        "Generate r2 zignatures from an analyzed, NAMED target (`zg` + `zos`) and save to a file. " +
        "Use a SYMBOLED reference (e.g. compiled open brcmfmac/bcmdhd) — run analyze({depth:'full'}) " +
        "on it first so functions exist. Apply the file to a stripped target with apply_signatures.",
      inputSchema: {
        target: z.string().describe("Open session name of the symboled REFERENCE binary."),
        out: z
          .string()
          .optional()
          .describe("Output .sigs path (default <RE_BINS>/.sigs/<target>.sigs)."),
      },
    },
    async ({ target, out }) =>
      guard(async () => {
        const h = sm.get(target);
        const file = out ?? path.join(SIG_DIR, projName(target) + ".sigs");
        fs.mkdirSync(path.dirname(file), { recursive: true });
        await h.cmd("zg"); // generate zignatures for analyzed functions
        await h.cmd(`zos ${file}`); // save to sdb file
        const count = (await h.cmd("z~?")).trim();
        return text(
          `generated zignatures -> ${file}\n  signatures: ${count}\n` +
            `  apply with: apply_signatures({ target: "<stripped>", sigfile: "${file}" })`
        );
      })
  );

  // apply_signatures — load a sig file and rename matching functions in a target.
  server.registerTool(
    "apply_signatures",
    {
      title: "Apply FLIRT signatures",
      description:
        "Load a zignature file and match + rename functions in a (stripped) target (`zo` + `z/`). " +
        "Recovers names onto matching functions; list_functions then shows them. Build the file " +
        "with make_signatures from a symboled reference of the same code.",
      inputSchema: {
        target: z.string().describe("Open session name of the STRIPPED target."),
        sigfile: z.string().describe("Path to a .sigs file produced by make_signatures."),
      },
    },
    async ({ target, sigfile }) =>
      guard(async () => {
        if (!fs.existsSync(sigfile)) throw new Error(`sigfile not found: ${sigfile}`);
        const h = sm.get(target);
        await h.cmd(`zo ${sigfile}`); // load zignatures
        const before = (await h.cmd("afl~?")).trim();
        const res = await h.cmd("z/"); // search + apply names to matches
        return capped(
          `applied ${sigfile} (target has ${before} functions).\n` +
            (res?.trim()
              ? res
              : "(no textual match report — check list_functions for recovered names)")
        );
      })
  );

  // list_signatures — show zignatures loaded in the session.
  server.registerTool(
    "list_signatures",
    {
      title: "List loaded signatures",
      description: "Show the zignatures currently loaded in the session (`z`).",
      inputSchema: { target: z.string().describe("Open session name.") },
    },
    async ({ target }) =>
      guard(async () => {
        const h = sm.get(target);
        return capped(await h.cmd("z"));
      })
  );
}
