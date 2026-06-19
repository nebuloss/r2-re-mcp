#!/usr/bin/env bash
# RE-MCP install script — runs INSIDE the LXC, in the community-scripts (ProxmoxVE) framework.
# Drop this in install/re-mcp-install.sh of a community-scripts fork.
# Copyright (c) 2026 nebuloss
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Provisions: Ghidra+GhidraMCP, radare2+r2-re-mcp (custom), filesystem MCP — as systemd HTTP MCP services.
source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

GHIDRA_VERSION="${GHIDRA_VERSION:-12.1.2}"
GHIDRA_MCP_REPO="${GHIDRA_MCP_REPO:-https://github.com/bethington/ghidra-mcp.git}"
GHIDRA_HOME=/opt/ghidra
GHIDRA_MCP_DIR=/opt/ghidra-mcp
GHIDRA_PROJECT_DIR=/opt/ghidra-projects/re
RE_BINS=/opt/re-bins
RE_WORK=/opt/re-work
# custom radare2 RE MCP server (THIS repo: github.com/nebuloss/r2-re-mcp)
R2_RE_MCP_REPO="${R2_RE_MCP_REPO:-https://github.com/nebuloss/r2-re-mcp.git}"
R2_RE_MCP_DIR="${R2_RE_MCP_DIR:-/opt/r2-re-mcp}"
R2_MCP_PORT="${R2_MCP_PORT:-8765}"      # custom server takes the canonical r2-MCP port (stock r2mcp gone)
MCPPROXY_VERSION="${MCPPROXY_VERSION:-0.40.0}"   # smart-mcp-proxy/mcpproxy-go (single aggregated endpoint)
PORT_MCPPROXY="${PORT_MCPPROXY:-8090}"           # the SINGLE MCP interface this LXC exposes
# raw base for this repo's deploy/ helpers (override if you fork/rename or change branch)
RE_TOOLS_RAW="${RE_TOOLS_RAW:-https://raw.githubusercontent.com/nebuloss/r2-re-mcp/main/deploy}"

msg_info "Installing Dependencies (JDK 21, maven, python, node, build tools)"
$STD apt-get install -y \
  curl ca-certificates git unzip jq \
  openjdk-21-jdk maven \
  python3 python3-pip python3-venv \
  nodejs npm \
  build-essential pkg-config
msg_ok "Installed Dependencies"

msg_info "Installing Ghidra ${GHIDRA_VERSION}"
ASSET=$(curl -fsSL "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases" \
        | jq -r --arg v "$GHIDRA_VERSION" \
          '.[] | select(.tag_name | test($v)) | .assets[].browser_download_url' \
        | grep -m1 "_PUBLIC_.*\.zip")
curl -fsSL -o /tmp/ghidra.zip "$ASSET"
unzip -q /tmp/ghidra.zip -d /opt
ln -sfn /opt/ghidra_${GHIDRA_VERSION}_PUBLIC "$GHIDRA_HOME"
rm -f /tmp/ghidra.zip
# Strip GUI-only/doc/extension parts we never use (headless + GhidraMCP only).
# NOTE: Ghidra has no headless-only build — core framework + decompiler jars are
# shared with the GUI, so this is a SAFE-SUBSET trim, not a true headless build.
rm -rf "$GHIDRA_HOME/docs" \
       "$GHIDRA_HOME/Extensions/Eclipse" \
       "$GHIDRA_HOME/Extensions/IDAPro" \
       "$GHIDRA_HOME"/*.app 2>/dev/null || true
find "$GHIDRA_HOME/Ghidra/Features" -maxdepth 2 -type d -name help -exec rm -rf {} + 2>/dev/null || true
msg_info "Stripped Ghidra GUI/doc/extension parts (headless safe-subset trim)"
msg_ok "Installed Ghidra ${GHIDRA_VERSION}"

msg_info "Building GhidraMCP (bethington/ghidra-mcp)"
git clone --depth 1 "$GHIDRA_MCP_REPO" "$GHIDRA_MCP_DIR"
# current GhidraMCP needs its Ghidra jars installed into the local maven repo first
# (install-ghidra-deps reads --ghidra-path); raw `mvn clean package` can't resolve them.
(cd "$GHIDRA_MCP_DIR" \
  && $STD python3 -m tools.setup install-ghidra-deps --ghidra-path "$GHIDRA_HOME" \
  && GHIDRA_PATH="$GHIDRA_HOME" $STD python3 -m tools.setup build)
# Headless launch: current GhidraMCP dropped run_headless_server.sh; the headless
# server is launched by docker/entrypoint.sh (builds the Ghidra classpath from
# GHIDRA_HOME, runs GhidraMCPHeadlessServer) and expects the jar at /app/GhidraMCP.jar.
# Stage both for the systemd unit (entrypoint.sh may lack +x).
chmod +x "$GHIDRA_MCP_DIR/docker/entrypoint.sh"
mkdir -p /app && cp -f "$GHIDRA_MCP_DIR"/target/GhidraMCP-*.jar /app/GhidraMCP.jar
$STD pip3 install --break-system-packages -r "$GHIDRA_MCP_DIR/requirements.txt"
mkdir -p "$GHIDRA_PROJECT_DIR"
msg_ok "Built GhidraMCP"

msg_info "Installing radare2 (+ r2ghidra/r2dec decompiler plugins)"
git clone --depth 1 https://github.com/radareorg/radare2 /opt/radare2
(cd /opt/radare2 && $STD ./sys/install.sh)
$STD r2pm -U
# Decompiler plugins the custom server's decompile/pdg path uses.
$STD r2pm -ci r2ghidra r2dec || true
msg_ok "Installed radare2"

msg_info "Building custom r2-re-mcp server (replaces stock r2mcp)"
# Node/npm installed above; the custom server needs r2 + r2pipe at runtime.
git clone --depth 1 "$R2_RE_MCP_REPO" "$R2_RE_MCP_DIR"
(cd "$R2_RE_MCP_DIR" && $STD npm install --no-fund --no-audit && $STD npm run build)
msg_ok "Built r2-re-mcp"

msg_info "Installing filesystem MCP (server-filesystem; mcpproxy spawns it via stdio)"
# NO supergateway: it spawned a fresh stdio child per HTTP session and never
# reaped them (observed 339 leaked node procs / ~4.9G → cgroup OOM). mcpproxy
# runs mcp-server-filesystem directly as a stdio upstream (one supervised child).
$STD npm install -g @modelcontextprotocol/server-filesystem
mkdir -p "$RE_BINS" "$RE_WORK"
msg_ok "Installed filesystem MCP"

msg_info "Creating systemd MCP services"
cat >/etc/systemd/system/ghidra-headless.service <<EOF
[Unit]
Description=Ghidra MCP Headless Server (REST backend 127.0.0.1:8089)
After=network.target
[Service]
Type=simple
WorkingDirectory=${GHIDRA_MCP_DIR}
Environment=GHIDRA_HOME=${GHIDRA_HOME}
Environment=GHIDRA_MCP_PORT=8089
Environment=GHIDRA_MCP_BIND_ADDRESS=127.0.0.1
# Allow /run_script_inline so references can be CREATED for computed-pointer
# accesses the analyzer can't link (read-only xref tools cannot add refs).
# Backend binds loopback only; exposure is via the bridge on the lab subnet.
Environment=GHIDRA_MCP_ALLOW_SCRIPTS=1
Environment=PROJECT_PATH=${GHIDRA_PROJECT_DIR}
Environment="JAVA_OPTS=-Xmx5g -XX:+UseG1GC"
# Launch via the repo's entrypoint (builds Ghidra classpath, runs GhidraMCPHeadlessServer);
# reads GHIDRA_HOME/GHIDRA_MCP_PORT/GHIDRA_MCP_BIND_ADDRESS/PROJECT_PATH; jar at /app/GhidraMCP.jar.
ExecStart=/usr/bin/bash ${GHIDRA_MCP_DIR}/docker/entrypoint.sh
Restart=on-failure
RestartSec=5
TimeoutStartSec=300
# Blast-radius guard: cap above the -Xmx5g heap so a Ghidra runaway is OOM'd in
# ITS OWN cgroup instead of taking down the whole container (and every agent).
MemoryHigh=5632M
MemoryMax=6G
[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/ghidra-mcp.service <<EOF
[Unit]
Description=Ghidra MCP Bridge (streamable-http :8081 -> backend :8089)
After=network.target ghidra-headless.service
Requires=ghidra-headless.service
PartOf=ghidra-headless.service
[Service]
Type=simple
WorkingDirectory=${GHIDRA_MCP_DIR}
Environment=GHIDRA_MCP_URL=http://127.0.0.1:8089
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 120); do curl -sf -o /dev/null http://127.0.0.1:8089/check_connection && exit 0; sleep 1; done; exit 1'
ExecStart=/usr/bin/python3 ${GHIDRA_MCP_DIR}/bridge_mcp_ghidra.py --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081
Restart=on-failure
RestartSec=5
TimeoutStartSec=180
MemoryMax=1G
[Install]
WantedBy=multi-user.target
EOF
# Install the repo's own unit for the custom server, then repoint its
# WorkingDirectory/ExecStart at $R2_RE_MCP_DIR and its port to $R2_MCP_PORT
# (the shipped unit hardcodes /opt/r2-re-mcp + 8766).
install -m 0644 "${R2_RE_MCP_DIR}/systemd/re-r2-mcp.service" /etc/systemd/system/re-r2-mcp.service
sed -i \
  -e "s#^WorkingDirectory=.*#WorkingDirectory=${R2_RE_MCP_DIR}#" \
  -e "s#^Environment=R2_MCP_PORT=.*#Environment=R2_MCP_PORT=${R2_MCP_PORT}#" \
  -e "s#^Environment=RE_BINS=.*#Environment=RE_BINS=${RE_BINS}#" \
  -e "s#^ExecStart=.*#ExecStart=/usr/bin/node ${R2_RE_MCP_DIR}/dist/server.js#" \
  /etc/systemd/system/re-r2-mcp.service
# NOTE: no filesystem-mcp.service — the filesystem server is launched by mcpproxy
# itself as a stdio upstream (see the "files" entry in mcp_config.json below), so
# there is no long-lived http bridge and no per-session child leak.
msg_ok "Created systemd MCP services (8081 ghidra / ${R2_MCP_PORT} re-r2-mcp; files = mcpproxy stdio child)"

msg_info "Installing mcpproxy (single aggregated MCP endpoint :${PORT_MCPPROXY})"
# smart-mcp-proxy/mcpproxy-go — one binary, no DB; transparently fronts all the
# local MCP servers behind ONE endpoint. Add/remove a backend = edit this config
# (clients keep using the single endpoint, unchanged).
if [[ ! -x /usr/local/bin/mcpproxy ]]; then
  curl -fsSL -o /tmp/mcpproxy.tgz \
    "https://github.com/smart-mcp-proxy/mcpproxy-go/releases/download/v${MCPPROXY_VERSION}/mcpproxy-${MCPPROXY_VERSION}-linux-amd64.tar.gz"
  tar -xzf /tmp/mcpproxy.tgz -C /tmp
  install -m 0755 "$(find /tmp -maxdepth 2 -name mcpproxy -type f | head -1)" /usr/local/bin/mcpproxy
  rm -f /tmp/mcpproxy.tgz
fi
mkdir -p /etc/mcpproxy /var/lib/mcpproxy
cat >/etc/mcpproxy/mcp_config.json <<EOF
{
  "listen": "0.0.0.0:${PORT_MCPPROXY}",
  "mcpServers": [
    { "name": "ghidra", "url": "http://127.0.0.1:8081/mcp", "protocol": "http", "enabled": true },
    { "name": "r2",     "url": "http://127.0.0.1:${R2_MCP_PORT}/mcp", "protocol": "http", "enabled": true },
    { "name": "files",  "command": "/usr/local/bin/mcp-server-filesystem", "args": ["${RE_WORK}", "${RE_BINS}"], "protocol": "stdio", "enabled": true }
  ]
}
EOF
cat >/etc/systemd/system/mcpproxy.service <<EOF
[Unit]
Description=MCPProxy — single aggregated MCP endpoint (streamable-http :${PORT_MCPPROXY}) fronting this host's MCP servers
# Do NOT order After= the upstream MCP units: mcpproxy connects asynchronously and
# retries; ordering after a perpetually-activating unit would stick this start job.
After=network.target
[Service]
Type=simple
Environment=HOME=/root
ExecStart=/usr/local/bin/mcpproxy serve -c /etc/mcpproxy/mcp_config.json -d /var/lib/mcpproxy -l 0.0.0.0:${PORT_MCPPROXY} --log-level info
Restart=on-failure
RestartSec=5
# Bounds mcpproxy AND the filesystem stdio child it spawns (same cgroup).
MemoryMax=2G
[Install]
WantedBy=multi-user.target
EOF
msg_ok "Installed mcpproxy"

systemctl daemon-reload
# filesystem-mcp.service intentionally absent — files is a stdio upstream of mcpproxy.
$STD systemctl enable --now ghidra-headless.service ghidra-mcp.service re-r2-mcp.service mcpproxy.service
msg_ok "Enabled MCP services (single endpoint :${PORT_MCPPROXY} fronts 8081 ghidra / ${R2_MCP_PORT} re-r2-mcp; files = stdio child)"

msg_info "Installing ingest helper (persistent, correct-base project import)"
if curl -fsSL "${RE_TOOLS_RAW}/ingest-re-bins.sh" -o "${GHIDRA_MCP_DIR}/ingest-re-bins.sh" 2>/dev/null; then
  chmod +x "${GHIDRA_MCP_DIR}/ingest-re-bins.sh"
  msg_ok "Installed ingest helper -> ${GHIDRA_MCP_DIR}/ingest-re-bins.sh"
else
  msg_info "Could not fetch ingest helper (set RE_TOOLS_RAW); copy tools/ingest-re-bins.sh in manually"
fi
# starter manifest (programs load transiently otherwise; edit after staging binaries).
# NOTE: backend opens the *.gpr INSIDE ${GHIDRA_PROJECT_DIR}; the helper targets it correctly.
if [ ! -f "${RE_BINS}/ingest.manifest" ]; then
  cat >"${RE_BINS}/ingest.manifest" <<'MEOF'
# ingest manifest for ingest-re-bins.sh  (file  language  base|-  [loader])
# rtecdc.bin    ARM:LE:32:Cortex    0xed0000    BinaryLoader   # CONFIRM fw base
# dhd.ko        AARCH64:LE:64:v8A    -           ElfLoader
# hmoswp.elf    ARM:LE:32:v8         -           ElfLoader
# ram dumps loaded raw can be 0x10000 high (pointer consts are firmware-VA);
# if so, strip the lead and load at 0:  dd if=ram.elf of=ram.shift.bin bs=64k skip=1
# ram.shift.bin  ARM:LE:32:Cortex  0x0  BinaryLoader
MEOF
  msg_ok "Wrote starter ${RE_BINS}/ingest.manifest"
fi

motd_ssh
customize

msg_info "Cleaning up"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"
