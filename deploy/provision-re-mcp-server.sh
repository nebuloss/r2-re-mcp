#!/usr/bin/env bash
# provision-re-mcp-server.sh
# ---------------------------------------------------------------------------
# Turn a FRESH Debian 13 (trixie) LXC/VM into the "dev-reverse" MCP
# reverse-engineering server used by the GT-BE98 open-WiFi-driver effort:
#
#   * Ghidra (headless) + GhidraMCP   -> HTTP MCP on :8081  (decompile/analysis)
#   * radare2 + r2-re-mcp (custom)    -> HTTP MCP on :8765  (disasm/search)
#   * @modelcontextprotocol filesystem + supergateway -> HTTP MCP on :8082
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
# custom radare2 RE MCP server (THIS repo: github.com/nebuloss/r2-re-mcp)
R2_RE_MCP_REPO="${R2_RE_MCP_REPO:-https://github.com/nebuloss/r2-re-mcp.git}"
R2_RE_MCP_DIR="${R2_RE_MCP_DIR:-/opt/r2-re-mcp}"
R2_MCP_PORT="${R2_MCP_PORT:-8765}"      # custom server takes the canonical r2-MCP port (stock r2mcp gone)
RE_BINS="${RE_BINS:-/opt/re-bins}"      # staged firmware/binaries (read by the MCPs)
RE_WORK="${RE_WORK:-/opt/re-work}"      # scratch / text artifacts (filesystem MCP)
RE_TOOLS_RAW="${RE_TOOLS_RAW:-https://raw.githubusercontent.com/nebuloss/r2-re-mcp/main/deploy}"  # for curl|bash use
PORT_GHIDRA_BACKEND=8089                 # headless REST (loopback only)
PORT_GHIDRA_MCP=8081                     # bridge (LAN)
PORT_R2MCP="$R2_MCP_PORT"                # custom r2-re-mcp server
PORT_FS_MCP=8082
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
    build-essential pkg-config

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
# build the plugin/headless jar (maven; output in target/GhidraMCP-*.jar)
( cd "$GHIDRA_MCP_DIR" && GHIDRA_INSTALL_DIR="$GHIDRA_HOME" mvn -q -DskipTests clean package )
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

# ---- 5. filesystem MCP (official server + supergateway) -------------------
log "filesystem MCP (npm globals)"
npm install -g @modelcontextprotocol/server-filesystem supergateway
mkdir -p "$RE_BINS" "$RE_WORK"

# ---- 6. systemd services --------------------------------------------------
log "systemd units"
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
ExecStart=${GHIDRA_MCP_DIR}/run_headless_server.sh --project ${GHIDRA_PROJECT_DIR}
Restart=on-failure
RestartSec=5
TimeoutStartSec=300
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
ExecStart=/usr/bin/python3 ${GHIDRA_MCP_DIR}/bridge_mcp_ghidra.py --transport streamable-http --mcp-host 0.0.0.0 --mcp-port ${PORT_GHIDRA_MCP}
Restart=on-failure
RestartSec=5
TimeoutStartSec=180
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

cat > /etc/systemd/system/filesystem-mcp.service <<EOF
[Unit]
Description=Filesystem MCP (official server-filesystem via supergateway, streamable-http :${PORT_FS_MCP})
After=network.target
[Service]
Type=simple
Environment=HOME=/root
ExecStart=/usr/local/bin/supergateway --stdio "mcp-server-filesystem ${RE_WORK} ${RE_BINS}" --outputTransport streamableHttp --port ${PORT_FS_MCP}
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ghidra-headless.service ghidra-mcp.service re-r2-mcp.service filesystem-mcp.service

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
for s in ghidra-headless ghidra-mcp re-r2-mcp filesystem-mcp; do
  printf "%-18s %s\n" "$s" "$(systemctl is-active $s)"
done
echo
echo "Endpoints (front with TLS subdomains on your reverse proxy):"
echo "  ghidra    -> http://<host>:${PORT_GHIDRA_MCP}/mcp"
echo "  re-r2-mcp -> http://<host>:${PORT_R2MCP}/mcp  (custom r2-re-mcp server)"
echo "  files     -> http://<host>:${PORT_FS_MCP}/mcp  (scoped: ${RE_WORK}, ${RE_BINS})"
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
