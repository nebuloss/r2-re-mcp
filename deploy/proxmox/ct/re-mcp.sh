#!/usr/bin/env bash
# RE-MCP container creator — run in the PROXMOX HOST shell (community-scripts/ProxmoxVE framework).
# Copyright (c) 2026 nebuloss
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: https://github.com/nebuloss/r2-re-mcp
#
# Creates a Debian 13 LXC and provisions the MCP reverse-engineering server
# (Ghidra+GhidraMCP, radare2+r2-re-mcp custom server, filesystem MCP) via install/re-mcp-install.sh.
#
# Usage (from a community-scripts fork that hosts these two files):
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/<you>/ProxmoxVE/main/ct/re-mcp.sh)"
#
# Conf-file support: build.func auto-loads per-app defaults from
#   /usr/local/community-scripts/defaults/re-mcp.vars   (offered "App Defaults for RE-MCP")
# and global defaults from /usr/local/community-scripts/default.vars ("User Defaults").
# Precedence: ENV var_* > .vars file > the var_* defaults below. See
# deploy/proxmox/re-mcp.vars.example for a ready-to-copy template (incl. VLAN pin).
source <(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/build.func)

APP="RE-MCP"
var_tags="${var_tags:-mcp;reverse-engineering;ghidra;radare2}"
var_cpu="${var_cpu:-4}"
var_ram="${var_ram:-8192}"      # Ghidra headless wants ~5G heap
var_disk="${var_disk:-40}"      # Ghidra + JDK + r2 + node + project
var_os="${var_os:-debian}"
var_version="${var_version:-13}"
var_unprivileged="${var_unprivileged:-1}"

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources
  if [[ ! -d /opt/ghidra-mcp ]]; then
    msg_error "No ${APP} installation found!"
    exit
  fi
  msg_info "Updating ${APP}"
  cd /opt/ghidra-mcp && git pull --ff-only 2>/dev/null || true
  if [[ -d /opt/r2-re-mcp/.git ]]; then
    cd /opt/r2-re-mcp && git pull --ff-only 2>/dev/null && npm install --no-fund --no-audit && npm run build || true
  fi
  systemctl restart ghidra-headless ghidra-mcp re-r2-mcp filesystem-mcp mcpproxy
  msg_ok "Updated ${APP}"
  exit
}

start
build_container
description

msg_ok "Completed Successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW} SINGLE aggregated MCP endpoint — front THIS one with a TLS subdomain; register ONLY it (type=http):${CL}"
echo -e "${TAB}${GATEWAY}${BGN}mcpproxy  http://${IP}:8090/mcp/   <-- the only endpoint clients use${CL}"
echo -e "${INFO}${YW} Backends behind it (loopback; not registered directly — add/remove in /etc/mcpproxy/mcp_config.json):${CL}"
echo -e "${TAB}${GATEWAY}${BGN}ghidra    http://127.0.0.1:8081/mcp${CL}"
echo -e "${TAB}${GATEWAY}${BGN}re-r2-mcp http://127.0.0.1:8765/mcp  (custom r2-re-mcp server)${CL}"
echo -e "${TAB}${GATEWAY}${BGN}files     http://127.0.0.1:8082/mcp${CL}"
echo -e "${INFO}${YW} Stage binaries into /opt/re-bins (scp/mount); then write ingest.manifest + run ingest-re-bins.sh.${CL}"
