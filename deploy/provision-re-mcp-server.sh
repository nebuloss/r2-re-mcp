#!/usr/bin/env bash
# provision-re-mcp-server.sh
# ---------------------------------------------------------------------------
# Turn a FRESH Debian 13 (trixie) LXC/VM into the "dev-reverse" MCP
# reverse-engineering server used by the GT-BE98 open-WiFi-driver effort:
#
#   * Ghidra (headless) + GhidraMCP   -> HTTP MCP on :8081  (decompile/analysis)
#   * radare2 + r2-re-mcp (custom)    -> HTTP MCP on :8765  (disasm/search)
#   * @modelcontextprotocol filesystem -> stdio upstream spawned by mcpproxy (no port)
#
# Spirit of the Proxmox VE Helper-Scripts: run as root inside a clean container.
# Idempotent-ish (safe to re-run). TLS/subdomains are handled by an EXTERNAL
# reverse proxy (e.g. *.mcp.<domain>/mcp -> these raw ports); not done here.
#
#   curl -fsSL <raw-url>/provision-re-mcp-server.sh | bash
#   # or: scp it in and `bash provision-re-mcp-server.sh`
# ---------------------------------------------------------------------------
set -euo pipefail

# ---- knobs (override via env) ---------------------------------------------
GHIDRA_VERSION="${GHIDRA_VERSION:-12.1.2}"
GHIDRA_MCP_REPO="${GHIDRA_MCP_REPO:-https://github.com/bethington/ghidra-mcp.git}"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
GHIDRA_MCP_DIR="${GHIDRA_MCP_DIR:-/opt/ghidra-mcp}"
GHIDRA_PROJECT_DIR="${GHIDRA_PROJECT_DIR:-/opt/ghidra-projects/re}"
# Project-relative path of the program auto-loaded as the *current program* on
# every backend (re)start. The headless backend opens the project but does NOT
# select a program on its own, so without this the bridge's analysis tools fail
# with "No program loaded" after any restart/reboot. Empty string disables.
GHIDRA_DEFAULT_PROGRAM="${GHIDRA_DEFAULT_PROGRAM:-/ram.shift.bin}"
# custom radare2 RE MCP server (THIS repo: github.com/nebuloss/r2-re-mcp)
R2_RE_MCP_REPO="${R2_RE_MCP_REPO:-https://github.com/nebuloss/r2-re-mcp.git}"
R2_RE_MCP_DIR="${R2_RE_MCP_DIR:-/opt/r2-re-mcp}"
R2_MCP_PORT="${R2_MCP_PORT:-8765}"      # custom server takes the canonical r2-MCP port (stock r2mcp gone)
RE_BINS="${RE_BINS:-/opt/re-bins}"      # staged firmware/binaries (read by the MCPs)
RE_WORK="${RE_WORK:-/opt/re-work}"      # scratch / text artifacts (filesystem MCP)
RE_SRC="${RE_SRC:-/opt/re-src}"         # reference driver source (search_source + filesystem MCP)
BRCMFMAC_SRC_REPO="${BRCMFMAC_SRC_REPO:-https://github.com/torvalds/linux}"  # mainline; sparse-checkout the brcm80211 subtree only
RE_TOOLS_RAW="${RE_TOOLS_RAW:-https://raw.githubusercontent.com/nebuloss/r2-re-mcp/main/deploy}"  # for curl|bash use
PORT_GHIDRA_BACKEND=8089                 # headless REST (loopback only)
PORT_GHIDRA_MCP=8081                     # bridge (LAN)
PORT_R2MCP="$R2_MCP_PORT"                # custom r2-re-mcp server
# PORT_FS_MCP removed — filesystem is a stdio child of mcpproxy (no listening port)
# NOTE: re-dyn-mcp (gdb/dynamic analysis) is NOT a mcpproxy upstream — it runs on
# dev-build (where QEMU+gdb+symbols are) and is registered DIRECTLY in the client's
# MCP config (a separate host shouldn't route through this container's local proxy).
MCPPROXY_VERSION="${MCPPROXY_VERSION:-0.40.0}"   # smart-mcp-proxy/mcpproxy-go (single aggregated endpoint)
PORT_MCPPROXY="${PORT_MCPPROXY:-8090}"           # the SINGLE MCP interface this LXC exposes
log(){ echo -e "\n\033[1;32m== $* ==\033[0m"; }

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

# ---- 1. base packages -----------------------------------------------------
log "apt base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl ca-certificates git unzip jq \
    openjdk-21-jdk maven \
    python3 python3-pip python3-venv pipx \
    nodejs npm \
    build-essential pkg-config \
    binwalk ripgrep universal-ctags

# ---- 2. Ghidra ------------------------------------------------------------
if [ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
  log "download Ghidra $GHIDRA_VERSION"
  # resolve the release asset URL dynamically (the zip carries a build datestamp)
  ASSET=$(curl -fsSL "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases" \
          | jq -r --arg v "$GHIDRA_VERSION" \
            '.[] | select(.tag_name | test($v)) | .assets[].browser_download_url' \
          | grep -m1 "_PUBLIC_.*\.zip")
  [ -n "$ASSET" ] || { echo "could not resolve Ghidra $GHIDRA_VERSION asset"; exit 1; }
  curl -fsSL -o /tmp/ghidra.zip "$ASSET"
  rm -rf /opt/ghidra_* "$GHIDRA_HOME"
  unzip -q /tmp/ghidra.zip -d /opt
  ln -sfn /opt/ghidra_${GHIDRA_VERSION}_PUBLIC "$GHIDRA_HOME"
  rm -f /tmp/ghidra.zip

  log "Ghidra headless strip (safe-subset GUI/doc/extension trim)"
  # Strip GUI-only/doc/extension parts we never use (headless + GhidraMCP only).
  # NOTE: Ghidra has no headless-only build — core framework + decompiler jars are
  # shared with the GUI, so this is a SAFE-SUBSET trim, not a true headless build.
  rm -rf "$GHIDRA_HOME/docs" \
         "$GHIDRA_HOME/Extensions/Eclipse" \
         "$GHIDRA_HOME/Extensions/IDAPro" \
         "$GHIDRA_HOME"/*.app 2>/dev/null || true
  find "$GHIDRA_HOME/Ghidra/Features" -maxdepth 2 -type d -name help -exec rm -rf {} + 2>/dev/null || true
else
  log "Ghidra already present ($GHIDRA_HOME)"
fi

# ---- 3. GhidraMCP (bethington/ghidra-mcp): build jar + python bridge ------
log "GhidraMCP (clone + maven build)"
if [ ! -d "$GHIDRA_MCP_DIR/.git" ]; then
  git clone --depth 1 "$GHIDRA_MCP_REPO" "$GHIDRA_MCP_DIR"
else
  git -C "$GHIDRA_MCP_DIR" pull --ff-only || true
fi
# Build the plugin/headless jar via the repo's setup tool (output target/GhidraMCP-*.jar).
# NOTE: current GhidraMCP requires its Ghidra jars installed into the local maven repo
# FIRST (`install-ghidra-deps`, which reads --ghidra-path/GHIDRA_PATH) — raw
# `mvn clean package` fails with "Could not find artifact ghidra:*:jar in central".
# `build` then compiles using the installed .m2 jars (it does NOT accept --ghidra-path).
( cd "$GHIDRA_MCP_DIR" \
  && python3 -m tools.setup install-ghidra-deps --ghidra-path "$GHIDRA_HOME" \
  && GHIDRA_PATH="$GHIDRA_HOME" python3 -m tools.setup build )
# Headless server launch: current GhidraMCP dropped run_headless_server.sh; the
# headless server is launched by docker/entrypoint.sh (builds the Ghidra classpath
# from GHIDRA_HOME, runs GhidraMCPHeadlessServer) and expects the jar at
# /app/GhidraMCP.jar. Stage both for the systemd unit. (entrypoint.sh may lack +x.)
chmod +x "$GHIDRA_MCP_DIR/docker/entrypoint.sh"
mkdir -p /app && cp -f "$GHIDRA_MCP_DIR"/target/GhidraMCP-*.jar /app/GhidraMCP.jar
# python deps for the streamable-http bridge
pip3 install --break-system-packages -r "$GHIDRA_MCP_DIR/requirements.txt"
mkdir -p "$GHIDRA_PROJECT_DIR"

# ---- 4. radare2 + custom r2-re-mcp server ---------------------------------
# Keep installing radare2 itself: the custom MCP server needs the `r2` binary
# and r2pipe at runtime.
if ! command -v r2 >/dev/null; then
  log "radare2 (git + sys/install)"
  git clone --depth 1 https://github.com/radareorg/radare2 /opt/radare2
  ( cd /opt/radare2 && ./sys/install.sh )
fi
# Decompiler plugins the custom server's decompile/pdg path uses (r2ghidra + r2dec).
log "r2 decompiler plugins (r2ghidra + r2dec)"
r2pm -U || true
r2pm -ci r2ghidra r2dec || true

# Build + install THIS repo's custom radare2 RE MCP server (replaces stock r2mcp).
# Node/npm were installed in step 1; verify before building.
log "r2-re-mcp (custom radare2 MCP server: build + install)"
command -v node >/dev/null && command -v npm >/dev/null \
  || { echo "node/npm missing (expected from base packages)"; exit 1; }
# If run from inside a checkout of this repo (deploy/ is a child of the repo
# root, whose package.json is @nebuloss/r2-re-mcp), use that tree; else clone.
_self_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
_repo_root="$(cd "${_self_dir}/.." 2>/dev/null && pwd || true)"
if [ -n "$_repo_root" ] && grep -q '@nebuloss/r2-re-mcp' "${_repo_root}/package.json" 2>/dev/null; then
  log "  using local repo checkout: $_repo_root"
  if [ "$_repo_root" != "$R2_RE_MCP_DIR" ]; then
    mkdir -p "$R2_RE_MCP_DIR"
    cp -a "$_repo_root"/. "$R2_RE_MCP_DIR"/
  fi
elif [ ! -d "$R2_RE_MCP_DIR/.git" ]; then
  git clone --depth 1 "$R2_RE_MCP_REPO" "$R2_RE_MCP_DIR"
else
  git -C "$R2_RE_MCP_DIR" pull --ff-only || true
fi
( cd "$R2_RE_MCP_DIR" && npm install --no-fund --no-audit && npm run build )

# ---- 4.5 re-utils-mcp (SEPARATE server: non-r2 utilities binwalk + source) -
# Keeps r2-re-mcp r2-only. mcpproxy fronts it as the "utils" upstream (:8780).
RE_UTILS_REPO="${RE_UTILS_REPO:-https://github.com/nebuloss/re-utils-mcp.git}"
RE_UTILS_DIR="${RE_UTILS_DIR:-/opt/re-utils-mcp}"
RE_UTILS_OK=0
log "re-utils-mcp (clone + build)"
if [ ! -d "$RE_UTILS_DIR/.git" ]; then
  git clone --depth 1 "$RE_UTILS_REPO" "$RE_UTILS_DIR" || echo "  ! re-utils-mcp clone failed (repo missing?) — utils server skipped"
else
  git -C "$RE_UTILS_DIR" pull --ff-only || true
fi
if [ -f "$RE_UTILS_DIR/package.json" ]; then
  ( cd "$RE_UTILS_DIR" && npm install --no-fund --no-audit && npm run build ) \
    && install -m 0644 "$RE_UTILS_DIR/systemd/re-utils-mcp.service" /etc/systemd/system/re-utils-mcp.service \
    && RE_UTILS_OK=1
fi

# ---- 5. filesystem MCP (official server; mcpproxy spawns it via stdio) -----
# NO supergateway: it spawned a fresh stdio child per HTTP session and never
# reaped them (observed 339 leaked node procs / ~4.9G → cgroup OOM). mcpproxy
# runs mcp-server-filesystem directly as a stdio upstream (one supervised child).
log "filesystem MCP (npm global; run as a stdio upstream by mcpproxy, no http bridge)"
npm install -g @modelcontextprotocol/server-filesystem
mkdir -p "$RE_BINS" "$RE_WORK" "$RE_SRC"

# ---- 5.5 reference open driver source (search_source + filesystem MCP) -----
# Sparse-checkout just the brcm80211 subtree of mainline (a few MB, not the whole
# kernel) so agents can cross-reference dhd.ko / firmware against the open driver.
log "reference driver source -> ${RE_SRC}/linux (sparse brcm80211)"
if [ ! -d "$RE_SRC/linux/.git" ]; then
  git clone --filter=blob:none --no-checkout --depth 1 "$BRCMFMAC_SRC_REPO" "$RE_SRC/linux" || true
  ( cd "$RE_SRC/linux" \
    && git sparse-checkout init --cone \
    && git sparse-checkout set drivers/net/wireless/broadcom/brcm80211 \
    && git checkout ) || echo "  ! source sparse-checkout failed (drop source into ${RE_SRC} manually)"
fi

# ---- 6. systemd services --------------------------------------------------
log "systemd units"
# Helper run as ghidra-headless ExecStartPost: once the REST backend is up, open
# the configured default program from the (already-analyzed) project so a
# *current program* exists. Uses the headless /load_program_from_project path
# (no re-analysis); best-effort so a load hiccup never fails/kills the backend.
cat > /usr/local/bin/ghidra-load-default-program <<'HLP'
#!/bin/sh
prog="${GHIDRA_DEFAULT_PROGRAM:-}"
port="${GHIDRA_MCP_PORT:-8089}"
[ -z "$prog" ] && exit 0
for i in $(seq 1 150); do
  curl -sf -o /dev/null "http://127.0.0.1:${port}/check_connection" && break
  sleep 1
done
curl -sf -X POST "http://127.0.0.1:${port}/load_program_from_project" \
     -H 'Content-Type: application/json' \
     -d "{\"path\":\"${prog}\"}" >/dev/null 2>&1 || true
exit 0
HLP
chmod +x /usr/local/bin/ghidra-load-default-program

cat > /etc/systemd/system/ghidra-headless.service <<EOF
[Unit]
Description=Ghidra MCP Headless Server (REST backend on 127.0.0.1:${PORT_GHIDRA_BACKEND})
After=network.target
[Service]
Type=simple
WorkingDirectory=${GHIDRA_MCP_DIR}
Environment=GHIDRA_HOME=${GHIDRA_HOME}
Environment=GHIDRA_MCP_PORT=${PORT_GHIDRA_BACKEND}
Environment=GHIDRA_MCP_BIND_ADDRESS=127.0.0.1
# Allow /run_script_inline (default-off since GhidraMCP v5.4.1). Required to
# *create* references for computed-pointer accesses the analyzer can't link
# (read-only xref tools cannot add references). Backend binds loopback only;
# exposure is via the bridge on the lab subnet. Set GHIDRA_MCP_AUTH_TOKEN here
# AND in ghidra-mcp.service if the bridge is reachable beyond a trusted net.
Environment=GHIDRA_MCP_ALLOW_SCRIPTS=1
Environment=PROJECT_PATH=${GHIDRA_PROJECT_DIR}
# Auto-load this project program as *current* after start (see helper above).
Environment=GHIDRA_DEFAULT_PROGRAM=${GHIDRA_DEFAULT_PROGRAM}
Environment="JAVA_OPTS=-Xmx5g -XX:+UseG1GC"
# Launch via the repo's entrypoint (builds Ghidra classpath, runs GhidraMCPHeadlessServer);
# reads GHIDRA_HOME/GHIDRA_MCP_PORT/GHIDRA_MCP_BIND_ADDRESS/PROJECT_PATH; jar at /app/GhidraMCP.jar.
ExecStart=/usr/bin/bash ${GHIDRA_MCP_DIR}/docker/entrypoint.sh
# After the backend is up, select a current program so the bridge's analysis
# tools work immediately (and survive reboots). Runs in the unit's env, so it
# sees GHIDRA_DEFAULT_PROGRAM/GHIDRA_MCP_PORT above.
ExecStartPost=/usr/local/bin/ghidra-load-default-program
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

cat > /etc/systemd/system/ghidra-mcp.service <<EOF
[Unit]
Description=Ghidra MCP Bridge (streamable-http :${PORT_GHIDRA_MCP} -> backend :${PORT_GHIDRA_BACKEND})
After=network.target ghidra-headless.service
Requires=ghidra-headless.service
PartOf=ghidra-headless.service
[Service]
Type=simple
WorkingDirectory=${GHIDRA_MCP_DIR}
Environment=GHIDRA_MCP_URL=http://127.0.0.1:${PORT_GHIDRA_BACKEND}
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 120); do curl -sf -o /dev/null http://127.0.0.1:${PORT_GHIDRA_BACKEND}/check_connection && exit 0; sleep 1; done; exit 1'
ExecStart=/usr/bin/python3 ${GHIDRA_MCP_DIR}/bridge_mcp_ghidra.py --transport streamable-http --mcp-host 127.0.0.1 --mcp-port ${PORT_GHIDRA_MCP}
Restart=on-failure
RestartSec=5
TimeoutStartSec=180
MemoryMax=1G
[Install]
WantedBy=multi-user.target
EOF

# Install the repo's own systemd unit for the custom server, then repoint its
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

# ---- mcpproxy: the SINGLE aggregated MCP endpoint this LXC exposes ---------
# smart-mcp-proxy/mcpproxy-go — one binary, no DB; transparently fronts all the
# local MCP servers behind one endpoint. Add/remove a backend = edit this config
# (agents keep using the one endpoint, unchanged).
log "mcpproxy (single aggregated MCP endpoint :${PORT_MCPPROXY})"
if [ ! -x /usr/local/bin/mcpproxy ]; then
  curl -fsSL -o /tmp/mcpproxy.tgz \
    "https://github.com/smart-mcp-proxy/mcpproxy-go/releases/download/v${MCPPROXY_VERSION}/mcpproxy-${MCPPROXY_VERSION}-linux-amd64.tar.gz"
  tar -xzf /tmp/mcpproxy.tgz -C /tmp
  install -m 0755 "$(find /tmp -maxdepth 2 -name mcpproxy -type f | head -1)" /usr/local/bin/mcpproxy
  rm -f /tmp/mcpproxy.tgz
fi
mkdir -p /etc/mcpproxy /var/lib/mcpproxy
cat > /etc/mcpproxy/mcp_config.json <<EOF
{
  "listen": "0.0.0.0:${PORT_MCPPROXY}",
  "call_tool_timeout": "5m0s",
  "mcpServers": [
    { "name": "ghidra", "url": "http://127.0.0.1:${PORT_GHIDRA_MCP}/mcp", "protocol": "http", "enabled": true },
    { "name": "r2",     "url": "http://127.0.0.1:${PORT_R2MCP}/mcp", "protocol": "http", "enabled": true },
    { "name": "files",  "command": "/usr/local/bin/mcp-server-filesystem", "args": ["${RE_WORK}", "${RE_BINS}", "${RE_SRC}"], "protocol": "stdio", "enabled": true },
    { "name": "utils",  "url": "http://127.0.0.1:8780/mcp", "protocol": "http", "enabled": true }
  ]
}
EOF
cat > /etc/systemd/system/mcpproxy.service <<EOF
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

systemctl daemon-reload
# NOTE: filesystem-mcp.service intentionally removed — files is a stdio upstream of mcpproxy.
systemctl enable --now ghidra-headless.service ghidra-mcp.service re-r2-mcp.service mcpproxy.service
[ "${RE_UTILS_OK:-0}" = 1 ] && systemctl enable --now re-utils-mcp.service

# ---- mcpproxy: auto-approve our trusted upstream tools --------------------
# mcpproxy QUARANTINES newly-discovered tools ("TOOL_QUARANTINED — must be
# inspected and approved before use"). Without this, agents get "not approved"
# instead of results on a FRESH deploy, and again whenever an upstream adds a
# tool. These are our own trusted servers, so approve them all once discovered.
# (api_key is written by mcpproxy into the config on first start; tools appear a
# few seconds after — hence the polling.)
log "mcpproxy: approve upstream tools"
APIKEY=""
for _ in $(seq 1 30); do
  APIKEY="$(jq -r '.api_key // empty' /etc/mcpproxy/mcp_config.json 2>/dev/null)"
  [ -n "$APIKEY" ] && break; sleep 2
done
# Wait until all 3 upstreams are connected (so approve_all sees their tools), then
# approve once each. GET /servers reports per-upstream connected/tool_count/status.
for _ in $(seq 1 45); do
  ready="$(curl -fsSL -m 10 "http://127.0.0.1:${PORT_MCPPROXY}/api/v1/servers" -H "X-API-Key: ${APIKEY}" 2>/dev/null \
           | grep -o '"connected":true' | wc -l)"
  [ "${ready:-0}" -ge 3 ] && break; sleep 2
done
for s in ghidra r2 files utils; do
  resp="$(curl -fsSL -m 10 -X POST "http://127.0.0.1:${PORT_MCPPROXY}/api/v1/servers/${s}/tools/approve" \
    -H "X-API-Key: ${APIKEY}" -H 'Content-Type: application/json' -d '{"approve_all":true}' 2>/dev/null || true)"
  echo "  ${s}: ${resp}"
done

# ---- 6.5 ingest helper (persistent, correct-base project import) ----------
# Programs load transiently otherwise (lost on restart). Stage the helper next
# to GhidraMCP so `ingest-re-bins.sh` is available once binaries are dropped in.
log "ingest helper"
_self_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -f "${_self_dir}/ingest-re-bins.sh" ]; then
  install -m 0755 "${_self_dir}/ingest-re-bins.sh" "${GHIDRA_MCP_DIR}/ingest-re-bins.sh"
  echo "  installed ingest helper from local repo"
elif curl -fsSL "${RE_TOOLS_RAW}/ingest-re-bins.sh" -o "${GHIDRA_MCP_DIR}/ingest-re-bins.sh" 2>/dev/null; then
  chmod +x "${GHIDRA_MCP_DIR}/ingest-re-bins.sh"
  echo "  fetched ingest helper from ${RE_TOOLS_RAW}"
else
  echo "  ! ingest helper not staged (set RE_TOOLS_RAW or copy tools/ingest-re-bins.sh)"
fi

# ---- 7. report ------------------------------------------------------------
log "status"
sleep 5
for s in ghidra-headless ghidra-mcp re-r2-mcp mcpproxy; do
  printf "%-18s %s\n" "$s" "$(systemctl is-active $s)"
done
echo
echo "SINGLE AGGREGATED MCP ENDPOINT (front THIS one with TLS on your reverse proxy):"
echo "  mcpproxy  -> http://<host>:${PORT_MCPPROXY}/mcp/   <-- register ONLY this in clients"
echo "               (transparently fronts ghidra+r2+files; add backends in"
echo "                /etc/mcpproxy/mcp_config.json — clients stay unchanged)"
echo
echo "Backends behind it (loopback; not registered in clients directly):"
echo "  ghidra    -> http://127.0.0.1:${PORT_GHIDRA_MCP}/mcp"
echo "  re-r2-mcp -> http://127.0.0.1:${PORT_R2MCP}/mcp  (custom r2-re-mcp server)"
echo "  files     -> stdio child of mcpproxy (mcp-server-filesystem; scoped: ${RE_WORK}, ${RE_BINS}) — no port"
echo
echo "Stage binaries into ${RE_BINS} (scp or a mount) — do NOT push multi-MB blobs through MCP."
echo
echo "PERSIST + CLEAN XREFS: the MCP loads programs transiently (lost on restart) and"
echo "a wrong base breaks pointer-constant xrefs. After staging binaries, write"
echo "${RE_BINS}/ingest.manifest then run tools/ingest-re-bins.sh to import them into"
echo "the project (analyzed, saved, correctly based). See that script's header for the"
echo "ram.elf 0x10000 image-base skew and the dd-shift workaround."
echo
echo "Register in the client's MCP config (type=http). Done."
