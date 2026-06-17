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

## After provisioning
- Endpoints: ghidra `:8081/mcp`, **re-r2-mcp** (custom `r2-re-mcp` server) `:8765/mcp`,
  filesystem `:8082/mcp` (scoped `/opt/re-work`,`/opt/re-bins`).
- **Front them with TLS subdomains** on your reverse proxy (e.g. `ghidra.mcp.<domain>/mcp → :8081`).
- **Stage firmware binaries** into `/opt/re-bins` via scp or a mount — do NOT push multi-MB blobs through MCP.
- Register the endpoints (type `http`) in each client's MCP config.

## What gets installed
- **Ghidra** (headless) — after unzip, a GUI/doc/extension **safe-subset strip** runs (removes
  `docs/`, `Extensions/{Eclipse,IDAPro}`, `*.app`, per-feature `help/`). Ghidra has no headless-only
  build, so framework/decompiler jars stay; this is a trim, not a true headless build.
- **GhidraMCP** (`bethington/ghidra-mcp`) — maven-built plugin + python streamable-http bridge.
- **radare2** + `r2ghidra`/`r2dec` decompiler plugins, plus the **custom `r2-re-mcp` server**
  (this repo, `github.com/nebuloss/r2-re-mcp`): cloned to `/opt/r2-re-mcp`, `npm run build`, served by
  the repo's `systemd/re-r2-mcp.service` (repointed to port 8765 / `/opt/r2-re-mcp` at install time).
- **filesystem MCP** (`@modelcontextprotocol/server-filesystem` via `supergateway`).

## Caveats (not yet validated on a live PVE host)
- Reconstructed from the running `dev-reverse` container + upstream projects
  (`bethington/ghidra-mcp`, `radareorg/radare2`, `nebuloss/r2-re-mcp`, official npm MCP packages).
  Syntax-checked only.
- First-run risk spots: the **GhidraMCP maven build** (`GHIDRA_INSTALL_DIR=… mvn clean package`),
  the **Ghidra release-asset resolution** (GitHub API), and the **`r2-re-mcp` `npm run build`**
  (tsc → `dist/server.js`). Versions/repos are env-overridable.
- The community-scripts `build.func`/`install.func` API evolves; the `ct`/`install` files follow
  the current convention and may need a minor tweak to match your framework revision.
