# @nebuloss/r2-re-mcp

A **custom, lean, task-specific radare2 MCP server** for the GT-BE98 / Broadcom
BCM6726b0 WiFi-driver reverse-engineering workflow.

## Why this exists

The stock `r2mcp` (on `:8765`) is thin and **stateless**: it re-opens/re-analyzes
the binary on every call and returns **unbounded** text. Agents end up bypassing
it for raw `ssh … r2`, which floods the context window with megadumps.

This server fixes that by being:

1. **Stateful** — one persistent `r2pipe` session per opened target, reused
   across every tool call (keyed by a friendly `name`). Analysis/flags/comments
   accumulate in-process and can be persisted via r2 projects.
2. **Token-disciplined** — every tool caps output at **≤200 lines AND ≤4000
   chars** by default, truncating with a clear `…[truncated N lines]` marker.
   No raw megadumps, ever.
3. **Recipe-encoded** — the team's r2 recipes (esp. the Thumb-2 recipe and the
   firmware addressing facts) are baked into the tools.
4. **Lean** — ~24 small, single-purpose tools (see below), no kitchen sink.
   Anything not first-class is reachable through the `r2cmd` escape hatch.

It runs **alongside** the stock r2mcp on a **new port (8766)** — it does not
clobber `:8765`.

## CRITICAL addressing & recipe facts (baked in)

- **Addresses are the firmware virtual address DIRECTLY.** e.g. the iDMA gate
  setter function is at firmware-VA `0xf335c`. This is **UNLIKE** the team's
  Ghidra setup, which carries a `+0x10000` image-base skew. **No 0x10000 offset
  is applied here.** For the raw blob `ram.shift.bin` the load base is `0`, so
  r2-addr == firmware-VA.
- **Thumb-2 disassembly recipe (mandatory).** `e asm.bits=16` alone does NOT
  work — r2 will decode ARM-32 garbage at a Thumb address. You must run:

  ```
  e asm.bits=16 ; ahb 16 @ ADDR ; pd N @ ADDR
  ```

  The `ahb 16 @ADDR` analysis hint is required. The `thumb_disasm` tool does
  exactly this for you.
- **Reference targets in `ram.shift.bin`:** `hme_sys_g = 0xeb700`, per-user
  gate `u16 @ 0xebb2c` (= `hme_sys_g + 0x42c`), iDMA gate setter fn `@ 0xf335c`.
- **Staged binaries** (in `RE_BINS`, default `/opt/re-bins`):
  - `ram.shift.bin` — dongle firmware, ARM Thumb-2, loaded raw (`-a arm -b 32`,
    base 0). Thumb is set per-region via `ahb`.
  - `rtecdc.bin` — dongle firmware blob.
  - `dhd.ko` — aarch64 ELF kernel module.
  - `hmoswp.elf` — ELF.

## Analysis depth matters (READ THIS)

The **xref, function, and call-graph tools return nothing until the binary is
analyzed.** A bare `open_target` runs light `aa` (`analysis:'basic'`), which
finds only a fraction of functions. For real navigation:

- open with `open_target({ name, analysis: 'full' })` (runs `aaa`), **or**
- call `analyze({ target, depth: 'full' })` afterward.

`aaa`/`emu` analysis can be **slow on a ~5 MB blob** — that's the trade-off.
`analyze` depths: `'basic'`=`aa` · `'full'`=`aaa` · `'refs'`=`aar`+`aac` ·
`'emu'`=`aae`+`aaae`.

## The tools (~24, grouped)

`addr-or-name`: every tool that takes a function/address argument accepts either
a hex/dec address (firmware-VA) **or** a symbol / flag / function name (resolved
via r2 — `?vi`, the flag table, or the function list).

### Session & analysis control

| Tool | What it does |
|------|--------------|
| `open_target({ name, arch?, bits?, baseAddr?, analysis? })` | Open/reuse a persistent session from `RE_BINS`. Defaults arch=arm, bits=32, base=0. `analysis`: `none` \| `basic`=aa (default) \| `full`=aaa. Auto-loads matching r2 project (`Po`). Returns file/size/arch/base/#functions. |
| `analyze({ target, depth? })` | Deepen analysis: `basic`=aa \| `full`=aaa (default) \| `refs`=aar+aac \| `emu`=aae+aaae. Returns function count. Slow on big blobs. |
| `close_target({ target })` | Close the session and free its r2 handle. |

### Triage / overview

| Tool | What it does |
|------|--------------|
| `info({ target })` | Consolidated metadata (`ij`+`iej`): arch, bits, format, endian, baddr, size, entrypoints. Compact key:value. |
| `sections({ target })` | Sections/segments (`iSj`): vaddr, vsize, perms, name. Capped. |
| `list_symbols({ target, kind?, filter? })` | `symbols`(`isj`, default) \| `imports`(`iij`) \| `exports`(`iEj`). Optional name `filter`. name+addr+type, capped. |
| `strings({ target, filter?, min? })` | Whole-binary strings (`izzj`), optional `filter` substring + `min` length (default 5). addr+string, capped. |

### Functions / navigation

| Tool | What it does |
|------|--------------|
| `list_functions({ target, filter? })` | Analyzed functions (`aflj`): name, addr, size, nargs, nbbs. Optional name `filter`. Capped; says so if none analyzed. |
| `function_info({ target, target_fn })` | One function (addr-or-name): name/addr/size/bits(16=Thumb)/bbs, args/locals (`afvj`), caller (`axtj`) + callee (`afxj`) counts. |
| `disasm_function({ target, target_fn })` | Whole-function disasm (`pdf`), **Thumb-aware** (applies `ahb 16` over the extent if the region is Thumb). Capped. |
| `rename({ target, addr, name })` | Function entry → `afn name`; otherwise sets a flag (`f name`). Durable only after `save_project`. |

### Call graph

| Tool | What it does |
|------|--------------|
| `callers({ target, target_fn })` | Sites referencing this fn (`axtj`): caller fn + site addr + type. Capped. |
| `callees({ target, target_fn })` | Calls made FROM this fn (`afxj`): site → target + type. Capped. |

### Disassembly / decompile / memory / search

| Tool | What it does |
|------|--------------|
| `thumb_disasm({ target, addr, n? })` | Thumb-2 disasm via the mandatory recipe. n=32. |
| `disasm({ target, addr, n? })` | Plain ARM disasm (`pd`). n=32. |
| `decompile({ target, addr })` | Decompile fn at addr: probes r2ghidra `pdg` > r2dec `pdd` > builtin `pdc`. |
| `read_mem({ target, addr, len? })` | Compact hexdump (`px`). len=64. |
| `search({ target, query, kind? })` | `bytes` (`/x`), `string` (`/`), or `value` (`/v`). Capped hit list. |
| `xrefs_to({ target, addr })` | Refs TO addr (`axtj`), trimmed: site / type / fn / one-line disasm. Capped. |
| `xrefs_from({ target, addr })` | Refs FROM addr (`axfj`), trimmed. Capped. |

### Emulation (ESIL)

| Tool | What it does |
|------|--------------|
| `emulate({ target, addr, steps? })` | Bounded ESIL run: `aei; aeim; aeip @addr` then `N aes` (default 16, ≤256), returns final registers (`aerj`) + PC. For understanding computed values (e.g. how the iDMA gate value is built). |

### Persistence & escape hatch

| Tool | What it does |
|------|--------------|
| `save_project({ target })` | Persist flags/comments/analysis via r2 project (`Ps <name>` into `R2_PROJECT_DIR`). Loading is automatic in `open_target`. |
| `annotate({ target, addr, flag?, comment? })` | Set a flag (`f`) and/or comment (`CCu`). Durable only after `save_project`. |
| `r2cmd({ target, cmd })` | **Escape hatch** — run any r2 command for anything not first-class above. Output still capped. |

## Stack

- TypeScript / Node 20+ / ESM.
- MCP: `@modelcontextprotocol/sdk` — `McpServer` + `StreamableHTTPServerTransport`
  (streamable-http), bound to `0.0.0.0:$R2_MCP_PORT`.
- radare2 via the `r2pipe` npm package (one persistent process per target).
- A `GET /health` endpoint is provided for proxy/systemd checks.

### Environment

| Var | Default | Meaning |
|-----|---------|---------|
| `R2_MCP_PORT` | `8766` | Listen port (NEW — does not clobber stock r2mcp on 8765). |
| `RE_BINS` | `/opt/re-bins` | Staged binaries directory. |
| `R2_PROJECT_DIR` | `/opt/re-bins/.r2projects` | r2 project storage. |
| `LOG_LEVEL` | `info` | `error`/`warn`/`info`/`debug` (logs go to **stderr** only). |

## Deploy / test — ON THE CONTAINER (10.0.50.147)

> This repo is source-only. **Do not build on dev-code.** Deploy to the RE MCP
> container, which already has radare2 + r2pipe deps from
> `provision-re-mcp-server.sh`.

```bash
# 1. get the source onto the container at /opt/r2-re-mcp
#    (rsync/scp/git-clone the tools/r2-re-mcp/ dir there)
sudo mkdir -p /opt/r2-re-mcp
sudo rsync -a --delete ./tools/r2-re-mcp/ /opt/r2-re-mcp/   # or git clone + cp

# 2. install deps + build
cd /opt/r2-re-mcp
npm install
npm run build            # tsc -> dist/server.js

# 3. install + start the systemd unit (runs alongside r2mcp on 8765)
sudo cp systemd/re-r2-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now re-r2-mcp
systemctl status re-r2-mcp
curl -s http://127.0.0.1:8766/health | jq .
```

### Register in a client `.mcp.json` (streamable-http)

To be fronted by the lab reverse proxy with TLS later; raw form:

```json
{
  "mcpServers": {
    "r2-re": {
      "type": "http",
      "url": "http://10.0.50.147:8766/mcp"
    }
  }
}
```

### Quick manual smoke test

After the service is up, drive it through any MCP client (or the inspector) and
run, in order:

1. `open_target({ name: "ram.shift.bin" })`
   → expect a summary: file `/opt/re-bins/ram.shift.bin`, arch `arm/32`,
     base `0x0`, some function count.
2. `thumb_disasm({ target: "ram.shift.bin", addr: "0xf335c" })`
   → expect Thumb-2 instructions (the iDMA gate setter), NOT ARM-32 garbage.
3. `xrefs_to({ target: "ram.shift.bin", addr: "0xebb2c" })`
   → expect the trimmed list of code sites that reference the per-user gate u16.

Then try `read_mem({ target: "ram.shift.bin", addr: "0xeb700", len: 64 })` to
peek at `hme_sys_g`, and `save_project({ target: "ram.shift.bin" })` to persist.

## Provisioning note (add to `provision-re-mcp-server.sh` later)

The provisioning script (`tools/provision-re-mcp-server.sh`) is **not modified**
here. To fold this service into provisioning, add a block alongside the existing
`r2mcp.service` unit, e.g.:

```bash
# ---- custom lean r2 RE MCP (alongside stock r2mcp) -----------------------
PORT_RE_R2MCP=8766
git -C /opt/r2-re-mcp pull --ff-only 2>/dev/null || \
  git clone --depth 1 <repo>/tools/r2-re-mcp /opt/r2-re-mcp   # or rsync from repo
( cd /opt/r2-re-mcp && npm install && npm run build )
cp /opt/r2-re-mcp/systemd/re-r2-mcp.service /etc/systemd/system/
# (then add re-r2-mcp to the `systemctl enable --now …` line and the status loop)
```

(Port `8766`; env-var style matches the other units.)
