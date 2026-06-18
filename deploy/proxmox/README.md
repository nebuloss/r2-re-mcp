# Proxmox provisioning for the MCP reverse-engineering server

Spin up the full `dev-reverse` MCP stack (Ghidra + GhidraMCP, radare2 + the custom
`r2-re-mcp` server, filesystem MCP) as a Debian 13 LXC. Three layers, pick what fits:

| File | Runs where | Needs |
|---|---|---|
| `../provision-re-mcp-server.sh` | **inside** a fresh Debian 13 LXC/VM (root) | nothing — installs everything |
| `create-re-mcp-ct.sh` | **Proxmox host shell** | nothing — creates the LXC **and** runs the provisioner. Self-contained. |
| `ct/re-mcp.sh` + `install/re-mcp-install.sh` | **Proxmox host shell**, via community-scripts framework | a fork of `community-scripts/ProxmoxVE` (see below) |

## Fastest path (no framework) — run in the Proxmox host shell
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/nebuloss/r2-re-mcp/main/deploy/proxmox/create-re-mcp-ct.sh)"
# override: CORES=6 MEMORY=12288 DISK=60 STORAGE=local-zfs CTID=147 bash ...
```
This `pct create`s the container and provisions it. **Most reliable** — no dependency on the
community-scripts framework internals.

## community-scripts (ProxmoxVE Helper-Scripts) wiring
The framework fetches `install/<app>-install.sh` from **its own repo by URL**, so a custom app
must live in a fork:
1. Fork `community-scripts/ProxmoxVE`.
2. Add these two files to the fork: `ct/re-mcp.sh` and `install/re-mcp-install.sh`.
3. In `ct/re-mcp.sh`, source `build.func` **from your fork** (so it resolves the install script
   from the same fork/branch), then run from the host shell:
   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/<you>/ProxmoxVE/main/ct/re-mcp.sh)"
   ```
This gives the full helper-script UX (resource prompts, OS/template selection, update mode).

## Conf-file defaults (`.vars`)
`build.func` auto-loads default settings — no code in our scripts is needed for this; it works
because `ct/re-mcp.sh` sources the current `build.func` and declares `var_*` defaults. The install
menu then offers:
- **User Defaults** → `/usr/local/community-scripts/default.vars` (global, all apps).
- **App Defaults for RE-MCP** → `/usr/local/community-scripts/defaults/re-mcp.vars` (this app only;
  the option appears once that file exists). After an **Advanced** install it offers to *save* your
  choices into this file.

Precedence: **ENV `var_*` > `.vars` file > the `var_*` defaults in `ct/re-mcp.sh`**. Only whitelisted
`var_*` keys are honored (e.g. `var_cpu/ram/disk`, `var_os/version`, `var_brg/net/vlan/gateway`,
`var_container_storage`, `var_tags`). For a **non-interactive pinned install** (e.g. onto VLAN 50),
copy the shipped template and edit it:
```bash
mkdir -p /usr/local/community-scripts/defaults
cp re-mcp.vars.example /usr/local/community-scripts/defaults/re-mcp.vars   # then uncomment var_vlan=50, etc.
```
See `deploy/proxmox/re-mcp.vars.example` for the full key list. Default settings are kept in the
script; the `.vars` file is the supported way to override without editing it.

## After provisioning
- **Single aggregated endpoint:** `mcpproxy` on `:8090/mcp/` transparently fronts all backends.
  Front **only this** with one TLS subdomain (e.g. `reverse.mcp.<domain>/mcp → :8090`) and register
  **only this** (type `http`) in each client's MCP config.
- Backends behind it (loopback, not registered directly): ghidra `127.0.0.1:8081/mcp`,
  **re-r2-mcp** (custom `r2-re-mcp` server) `127.0.0.1:8765/mcp`, filesystem `127.0.0.1:8082/mcp`
  (scoped `/opt/re-work`,`/opt/re-bins`). Add/remove a backend = edit `/etc/mcpproxy/mcp_config.json`;
  clients keep using the one endpoint unchanged.
- **Stage firmware binaries** into `/opt/re-bins` via scp or a mount — do NOT push multi-MB blobs through MCP.
  Then write `/opt/re-bins/ingest.manifest` and run `ingest-re-bins.sh` for a persistent, correctly-based import.

## What gets installed
- **Ghidra** (headless) — after unzip, a GUI/doc/extension **safe-subset strip** runs (removes
  `docs/`, `Extensions/{Eclipse,IDAPro}`, `*.app`, per-feature `help/`). Ghidra has no headless-only
  build, so framework/decompiler jars stay; this is a trim, not a true headless build.
- **GhidraMCP** (`bethington/ghidra-mcp`) — maven-built plugin + python streamable-http bridge.
- **radare2** + `r2ghidra`/`r2dec` decompiler plugins, plus the **custom `r2-re-mcp` server**
  (this repo, `github.com/nebuloss/r2-re-mcp`): cloned to `/opt/r2-re-mcp`, `npm run build`, served by
  the repo's `systemd/re-r2-mcp.service` (repointed to port 8765 / `/opt/r2-re-mcp` at install time).
- **filesystem MCP** (`@modelcontextprotocol/server-filesystem` via `supergateway`).
- **mcpproxy** (`smart-mcp-proxy/mcpproxy-go`, single Go binary, no DB) — the one aggregated
  endpoint on `:8090`; config at `/etc/mcpproxy/mcp_config.json`, state in `/var/lib/mcpproxy`.

## Caveats (not yet validated on a live PVE host)
- Reconstructed from the running `dev-reverse` container + upstream projects
  (`bethington/ghidra-mcp`, `radareorg/radare2`, `nebuloss/r2-re-mcp`, official npm MCP packages).
  Syntax-checked only.
- First-run risk spots: the **GhidraMCP build** (`tools.setup install-ghidra-deps --ghidra-path`
  then `tools.setup build`; headless launched via `docker/entrypoint.sh` + `/app/GhidraMCP.jar`),
  the **Ghidra release-asset resolution** (GitHub API), and the **`r2-re-mcp` `npm run build`**
  (tsc → `dist/server.js`). Versions/repos are env-overridable.
- The community-scripts `build.func`/`install.func` API evolves; the `ct`/`install` files follow
  the current convention and may need a minor tweak to match your framework revision.
