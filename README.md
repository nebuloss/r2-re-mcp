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
4. **Lean** — ~30 small, single-purpose tools (see below), no kitchen sink.
   Anything not first-class is reachable through the `r2cmd` escape hatch.
5. **Concurrency-safe** — r2pipe is a single pipe; this server is driven by
   **parallel agents**, so every `cmd`/`cmdj` on a session is **serialized**
   through a per-session promise-chain mutex (each command awaits the previous
   one before touching the pipe). No interleaved/corrupted output.

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

### Analysis auto-persist (no more re-running `aaa` every restart)

Re-running `aaa` (~30 s) on every restart is wasteful, so analysis is now
**persisted automatically**:

- After `analyze` completes it auto-saves the r2 project
  (`e dir.projects=$R2_PROJECT_DIR; Ps <projName>`), best-effort (a save failure
  never fails the tool — it's just reported).
- `open_target` loads a matching project **first** (`e dir.projects=…; P <projName>`
  over the already-open file). If the project already carries functions, the
  expensive `aa`/`aaa` is **skipped** and the open summary reports
  `analysis: recovered from project (skipped aa/aaa)` (`analysisFromProject=true`)
  — so a reopen is near-instant.
- `save_project` and `analyze`'s auto-save share the same code path.

> **Name sanitization (important).** r2 6.1.7 **rejects project names containing
> dots** (`Ps ram.shift.bin` → *"Invalid project name"*), which used to make
> saves *silently* succeed while reopen never loaded. Names are now sanitized to
> r2-safe form — every char outside `[A-Za-z0-9_]` becomes `_` (so
> `ram.shift.bin` → `ram_shift_bin`) — for **both** save and load. The on-disk
> project is a directory `$R2_PROJECT_DIR/<projName>/` containing `rc.r2`; load
> existence is checked against that `rc.r2`. (Benign `ERROR: ar: Unknown register`
> lines that always appear on load are filtered out before judging success.)

### Symbol import (bridge from Ghidra)

The blob has **no symbols** (everything is `fcn.000f335c`). The team's real
names live in the **bethington Ghidra project** — export them separately (a
Ghidra script dumping `{name, addr, kind}` to JSON or CSV under `RE_BINS`), then:

```text
import_symbols({ target: "ram.shift.bin", file: "bethington-syms.json" })
save_project({ target: "ram.shift.bin" })   # make the names durable
```

After that, xrefs / decompile / callgraph render readable names. Inline use is
also supported: `import_symbols({ target, symbols: [{ name, addr, kind }] })`.
Names are sanitized to be r2-flag-safe (`[A-Za-z0-9_.]`); `kind:"function"` also
defines+names the function (`af`/`afn`). Addresses are firmware-VA directly (NO
+0x10000 — strip the Ghidra image-base skew during export).

### Pagination

The high-volume tools — `list_functions`, `list_symbols`, `strings`, `search`,
`disasm`, `disasm_function` — accept optional `offset` (default 0) and `limit`.
Windowing is applied **before** the output cap; when windowed, a footer
`[showing N..M of TOTAL — pass offset=M to continue]` is appended so you can page
through without flooding context. Omitting both preserves the original behavior.

### Decompilers

`decompile` probes for the best available decompiler in this order:
**r2ghidra (`pdg`) > r2dec (`pdd`) > builtin pseudo (`pdc`)**. `pdg`/`pdd` are
the **preferred** decompilers — install r2ghidra and/or r2dec on the container
for good output; `pdc` is the always-present fallback.

## The tools (~30, grouped)

`addr-or-name`: every tool that takes a function/address argument accepts either
a hex/dec address (firmware-VA) **or** a symbol / flag / function name (resolved
via r2 — `?vi`, the flag table, or the function list).

### Session & analysis control

| Tool | What it does |
|------|--------------|
| `open_target({ name, arch?, bits?, baseAddr?, analysis? })` | Open/reuse a persistent session from `RE_BINS`. Defaults arch=arm, bits=32, base=0. `analysis`: `none` \| `basic`=aa (default) \| `full`=aaa. Auto-loads matching r2 project (`P <projName>`) **first**; if it carries analysis, skips aa/aaa (`analysisFromProject`). Returns file/size/arch/base/#functions. |
| `analyze({ target, depth?, save? })` | Deepen analysis: `basic`=aa \| `full`=aaa (default) \| `refs`=aar+aac \| `emu`=aae+aaae. **Auto-saves the r2 project on completion** (best-effort; `save:false` to skip). Returns function count. Slow on big blobs. |
| `close_target({ target })` | Close the session and free its r2 handle. |

### Triage / overview

| Tool | What it does |
|------|--------------|
| `info({ target })` | Consolidated metadata (`ij`+`iej`): arch, bits, format, endian, baddr, size, entrypoints. **Also surfaces live `e asm.arch/asm.bits/asm.endian` + cfg baddr/entry** so RAW blobs (no bin metadata) still report arch/bits. Compact key:value. |
| `sections({ target })` | Sections/segments (`iSj`): vaddr, vsize, perms, name. Capped. |
| `list_symbols({ target, kind?, filter?, offset?, limit? })` | `symbols`(`isj`, default) \| `imports`(`iij`) \| `exports`(`iEj`). Optional name `filter`. Paginated. name+addr+type, capped. |
| `strings({ target, filter?, min?, offset?, limit? })` | Whole-binary strings (`izzj`), optional `filter` substring + `min` length (default 5). Paginated. addr+string, capped. |

### Functions / navigation

| Tool | What it does |
|------|--------------|
| `list_functions({ target, filter?, offset?, limit? })` | Analyzed functions (`aflj`): name, addr, size, nargs, nbbs. Optional name `filter`. Paginated. Capped; says so if none analyzed. |
| `function_info({ target, target_fn })` | One function (addr-or-name): name/addr/size/bits(16=Thumb)/bbs, args/locals (`afvj`), caller (`axtj`) + callee (`afxj`) counts. |
| `disasm_function({ target, target_fn, grep?, offset?, limit? })` | Whole-function disasm (`pdf`), **Thumb-aware** (applies `ahb 16` over the extent if the region is Thumb). Optional `grep` line filter (case-insensitive regex; substring fallback) applied before capping. Paginated (windows disasm lines). Capped. |
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
| `disasm({ target, addr, n?, arch?, bits?, grep?, offset?, limit? })` | Plain ARM disasm (`pd`). n=32. Optional per-call `arch`+`bits` (BOTH required) append `@a:<arch>:<bits>` — the clean per-call alternative to `thumb_disasm`'s global `ahb` (e.g. `arch:"arm",bits:16` for Thumb; `bits:64` for aarch64 like `dhd.ko`). Optional `grep` line filter before capping. Paginated (windows disasm lines). |
| `disasm_batch({ target, regions, grep? })` | Disassemble **several regions in one call** (token saver). Each region `{ addr, n?=24, arch?, bits?, label? }`; blocks are separated by `=== <label\|addr> ===` markers, then the whole thing is capped. Optional top-level `grep` filters the combined output. Max 20 regions. |
| `decompile({ target, addr })` | Decompile fn at addr: probes r2ghidra `pdg` > r2dec `pdd` > builtin `pdc` (pdg/pdd preferred when installed). |
| `read_mem({ target, addr, len? })` | Compact hexdump (`px`). len=64. |
| `search({ target, query, kind?, offset?, limit? })` | `bytes` (`/x`), `string` (`/`), or `value` (`/v`). Paginated. Capped hit list. |
| `xrefs_to({ target, addr })` | Refs TO addr (`axtj`), trimmed: site / type / fn / one-line disasm. Capped. |
| `xrefs_from({ target, addr })` | Refs FROM addr (`axfj`), trimmed. Capped. |

### Emulation (ESIL)

| Tool | What it does |
|------|--------------|
| `emulate({ target, addr, steps? })` | Bounded ESIL run: `aei; aeim; aeip @addr` then `N aes` (default 16, ≤256), returns final registers (`aerj`) + PC. For understanding computed values (e.g. how the iDMA gate value is built). |

### Symbols / types / diff (NEW)

| Tool | What it does |
|------|--------------|
| `import_symbols({ target, file?, symbols? })` | **Bridge from Ghidra.** Set flags from `{name,addr,kind?}` (inline `symbols` and/or a `file` — JSON array or CSV `name,addr[,kind]`, resolved under `RE_BINS`). `kind:"function"` also defines+names the fn (`af`/`afn`). Names sanitized r2-flag-safe. Canonical source = bethington Ghidra project (export separately). Persist with `save_project`. |
| `define_type({ target, cdef })` | Define a C type/struct in the session type DB (`td "<cdef>"`). Returns success/parse error. |
| `apply_type({ target, addr, type })` | Format/print memory at `addr` as `type` (`tp <type> @ addr`); returns the field-labelled view (capped). |
| `list_types({ target, filter? })` | List known types (`tj`/`t`), optional name `filter`. Compact, capped. |
| `diff_functions({ targetA, fnA, targetB, fnB })` | **Best-effort** cross-binary fn diff. Uses `radiff2 -AC` if on PATH, else a normalized line-by-line disasm diff (addresses/immediates masked). Both targets must be open. Capped. |

### Persistence & escape hatch

| Tool | What it does |
|------|--------------|
| `save_project({ target })` | Persist flags/comments/analysis via r2 project (`Ps <name>` into `R2_PROJECT_DIR`). Loading is automatic in `open_target`; `analyze` auto-saves too. |
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

### Automated live smoke test (`test/smoke.mjs`)

A runnable MCP client that connects over streamable-http, lists tools, and runs
the core flow `open_target → info → analyze → list_functions → function_info →
xrefs_to → emulate`, printing each (already-capped) result. **It needs a live
deployed server** (radare2 + a staged binary) — it is *not* a CI test (CI only
typechecks; radare2 isn't on GitHub runners):

```bash
# against a deployed container:
R2_MCP_URL=http://10.0.50.147:8766/mcp SMOKE_TARGET=ram.shift.bin \
  npm run smoke
# or locally if the server is up on 8766:
npm run smoke
```

Env: `R2_MCP_URL` (default `http://127.0.0.1:8766/mcp`), `SMOKE_TARGET`
(default `ram.shift.bin`), `SMOKE_FN` (default `0xf335c`), `SMOKE_XREF`
(default `0xebb2c`). Exits non-zero on connection or required-step failure.

## CI

`.github/workflows/ci.yml` runs on push/PR: `npm ci` + `npm run build` (tsc
typecheck) on Node 20. It deliberately does **not** run the r2-dependent smoke
test — radare2 isn't available on GitHub runners.

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
