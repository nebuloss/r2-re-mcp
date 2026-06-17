#!/usr/bin/env node
/**
 * test/smoke.mjs — LIVE smoke test for a DEPLOYED r2-re-mcp server.
 *
 * This is NOT a CI test: it needs a running server with radare2 + a staged
 * binary (default ram.shift.bin under RE_BINS on the container). Run it against
 * a deployed instance:
 *
 *   R2_MCP_URL=http://10.0.50.147:8766/mcp \
 *   SMOKE_TARGET=ram.shift.bin \
 *   node test/smoke.mjs
 *
 * Defaults: URL http://127.0.0.1:8766/mcp, target ram.shift.bin.
 *
 * It connects over streamable-http, lists tools, then exercises the core RE
 * flow: open_target -> info -> analyze -> list_functions -> function_info ->
 * xrefs_to -> emulate, printing each (already-capped) result. Exit code is
 * non-zero if the connection or any required step fails.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const MCP_URL = process.env.R2_MCP_URL ?? "http://127.0.0.1:8766/mcp";
const TARGET = process.env.SMOKE_TARGET ?? "ram.shift.bin";
// Reference firmware-VA targets in ram.shift.bin (override for other blobs).
const FN_ADDR = process.env.SMOKE_FN ?? "0xf335c"; // iDMA gate setter fn
const XREF_ADDR = process.env.SMOKE_XREF ?? "0xebb2c"; // per-user gate u16

function textOf(result) {
  if (!result || !Array.isArray(result.content)) return "(no content)";
  return result.content.map((c) => (c.type === "text" ? c.text : `[${c.type}]`)).join("\n");
}

async function call(client, name, args) {
  process.stdout.write(`\n=== ${name}(${JSON.stringify(args)}) ===\n`);
  try {
    const res = await client.callTool({ name, arguments: args });
    const body = textOf(res);
    process.stdout.write(body + "\n");
    if (res.isError) process.stdout.write(`  ! tool reported isError\n`);
    return res;
  } catch (e) {
    process.stdout.write(`  ! call failed: ${e?.message ?? e}\n`);
    throw e;
  }
}

async function main() {
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL));
  const client = new Client({ name: "r2-re-mcp-smoke", version: "2.1.0" });

  process.stdout.write(`connecting to ${MCP_URL} …\n`);
  await client.connect(transport);

  const tools = await client.listTools();
  const names = (tools.tools ?? []).map((t) => t.name).sort();
  process.stdout.write(`connected. ${names.length} tools:\n  ${names.join(", ")}\n`);

  // Core RE flow. analyze is slow (aaa) but exercises the auto-save path.
  await call(client, "open_target", { name: TARGET });
  await call(client, "info", { target: TARGET });
  await call(client, "analyze", { target: TARGET, depth: "full" });
  await call(client, "list_functions", { target: TARGET, limit: 20 });
  await call(client, "function_info", { target: TARGET, target_fn: FN_ADDR });
  await call(client, "xrefs_to", { target: TARGET, addr: XREF_ADDR });
  await call(client, "emulate", { target: TARGET, addr: FN_ADDR, steps: 8 });

  await client.close();
  process.stdout.write("\nsmoke test OK.\n");
}

main().catch((e) => {
  process.stderr.write(`\nSMOKE TEST FAILED: ${e?.stack ?? e}\n`);
  process.exit(1);
});
