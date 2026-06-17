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
  systemctl restart ghidra-headless ghidra-mcp re-r2-mcp filesystem-mcp
  msg_ok "Updated ${APP}"
  exit
}

start
build_container
description

msg_ok "Completed Successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW} MCP endpoints (front with TLS subdomains on your reverse proxy):${CL}"
echo -e "${TAB}${GATEWAY}${BGN}ghidra    http://${IP}:8081/mcp${CL}"
echo -e "${TAB}${GATEWAY}${BGN}re-r2-mcp http://${IP}:8765/mcp  (custom r2-re-mcp server)${CL}"
echo -e "${TAB}${GATEWAY}${BGN}files     http://${IP}:8082/mcp${CL}"
echo -e "${INFO}${YW} Stage binaries into /opt/re-bins (scp/mount); register endpoints (type=http) in the client.${CL}"
