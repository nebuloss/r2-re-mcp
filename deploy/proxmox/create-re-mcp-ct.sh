#!/usr/bin/env bash
# create-re-mcp-ct.sh — run in the PROXMOX HOST shell.
# Self-contained (NO community-scripts dependency): creates a Debian 13 LXC and
# provisions the MCP reverse-engineering server inside it via provision-re-mcp-server.sh.
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/nebuloss/r2-re-mcp/main/deploy/proxmox/create-re-mcp-ct.sh)"
#
# Override any var via env, e.g.:  CORES=6 MEMORY=12288 DISK=60 STORAGE=local-zfs bash create-re-mcp-ct.sh
set -euo pipefail

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
CT_HOSTNAME="${CT_HOSTNAME:-dev-reverse}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
CORES="${CORES:-4}"
MEMORY="${MEMORY:-8192}"     # Ghidra headless ~5G heap
DISK="${DISK:-40}"
BRIDGE="${BRIDGE:-vmbr0}"
PROVISION_URL="${PROVISION_URL:-https://raw.githubusercontent.com/nebuloss/r2-re-mcp/main/deploy/provision-re-mcp-server.sh}"

echo "== fetching a Debian 13 template =="
pveam update >/dev/null 2>&1 || true
TMPL=$(pveam available --section system | awk '/debian-13-standard/{print $2}' | sort -V | tail -1)
[ -n "$TMPL" ] || { echo "no debian-13 template available (pveam available)"; exit 1; }
pveam download "$TEMPLATE_STORAGE" "$TMPL" 2>/dev/null || true

echo "== creating LXC $CTID ($CT_HOSTNAME): ${CORES}c/${MEMORY}M/${DISK}G on $STORAGE =="
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TMPL}" \
  --hostname "$CT_HOSTNAME" \
  --cores "$CORES" --memory "$MEMORY" --swap 512 \
  --rootfs "${STORAGE}:${DISK}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
  --features nesting=1 \
  --unprivileged 1 --onboot 1

pct start "$CTID"
echo "== waiting for network =="
for i in $(seq 1 30); do pct exec "$CTID" -- bash -c 'getent hosts github.com' >/dev/null 2>&1 && break; sleep 2; done

echo "== provisioning MCP stack inside the container =="
pct exec "$CTID" -- bash -c "apt-get update -qq && apt-get install -y curl >/dev/null 2>&1; curl -fsSL '$PROVISION_URL' | bash"

IP=$(pct exec "$CTID" -- hostname -I | awk '{print $1}')
echo
echo "== DONE — RE-MCP container $CTID ($CT_HOSTNAME) @ $IP =="
echo "   ghidra    http://$IP:8081/mcp"
echo "   re-r2-mcp http://$IP:8765/mcp  (custom r2-re-mcp server)"
echo "   files     http://$IP:8082/mcp"
echo "   Stage binaries into /opt/re-bins; front with TLS subdomains on your reverse proxy."
