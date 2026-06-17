/**
 * tools/emulate.ts — ESIL emulation tool.
 *
 * `emulate` runs r2's ESIL VM for a bounded number of steps from an address and
 * returns the final register state. Useful for understanding *computed* values
 * (e.g. how the iDMA per-user gate value/mask is assembled before the store).
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SessionManager } from "../sessions.js";
import { guard, capped, hex, resolveAddr } from "./common.js";

const MAX_STEPS = 256;

/** Registers worth surfacing first for ARM/Thumb; the rest follow if present. */
const PRIORITY_REGS = [
  "pc",
  "sp",
  "lr",
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
];

export function registerEmulateTools(server: McpServer, sm: SessionManager): void {
  server.registerTool(
    "emulate",
    {
      title: "Emulate (ESIL)",
      description:
        "Bounded ESIL emulation from `addr`: inits the VM (`aei; aeim`), seeks PC there " +
        "(`aeip`), single-steps `steps` times (`aes`, default 16, capped at 256), then returns " +
        "the final register state (`aerj`) compactly with PC highlighted. Use to understand " +
        "computed values (e.g. how the iDMA gate value is built). Thumb is honored via the " +
        "session's analysis bits; for a Thumb sub-routine ensure it's analyzed/hinted first.",
      inputSchema: {
        target: z.string().describe("Open session name."),
        addr: z
          .union([z.string(), z.number()])
          .describe("Start address (firmware-VA) or function name."),
        steps: z.number().int().optional().describe("ESIL steps, default 16, capped at 256."),
      },
    },
    async ({ target, addr, steps }) =>
      guard(async () => {
        const h = sm.get(target);
        const a = await resolveAddr(h, addr);
        const n = Math.max(1, Math.min(steps ?? 16, MAX_STEPS));

        // Init the ESIL VM and its memory, then point PC at the start address.
        await h.cmd("aei");
        await h.cmd("aeim");
        await h.cmd(`aeip @ ${a}`);

        // Single-step n times. `aes` steps one ESIL instruction; loop in r2 with a
        // repeat prefix to avoid n round-trips.
        await h.cmd(`${n}aes`);

        const regs = (await h.cmdj("aerj")) ?? {};
        const pc = regs.pc !== undefined ? hex(regs.pc) : "?";

        const seen = new Set<string>();
        const lines: string[] = [];
        for (const r of PRIORITY_REGS) {
          if (regs[r] !== undefined) {
            lines.push(`${r.padEnd(4)} = ${hex(regs[r])}`);
            seen.add(r);
          }
        }
        for (const k of Object.keys(regs)) {
          if (!seen.has(k) && typeof regs[k] === "number") {
            lines.push(`${k.padEnd(4)} = ${hex(regs[k])}`);
          }
        }
        const body =
          `ESIL: stepped ${n} from ${a}; PC now ${pc}\n` +
          (lines.length ? lines.join("\n") : "(no register state — ESIL init may have failed)");
        return capped(body);
      })
  );
}
