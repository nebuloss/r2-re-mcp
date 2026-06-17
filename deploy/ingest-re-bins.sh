#!/usr/bin/env bash
# ingest-re-bins.sh
# ---------------------------------------------------------------------------
# Import the staged RE binaries into the Ghidra project as PERSISTENT
# DomainFiles (analyzed + saved), instead of the transient `load_program`
# path the MCP uses by default.
#
# Why this exists:
#   * Transient loads cannot be saved ("Location does not exist for a save
#     operation") -> every backend restart loses ALL analysis and the
#     open-program list. Persistent import makes restarts cheap and lets
#     `load_program_from_project` reopen instantly with analysis intact.
#   * It also fixes XREFS: a binary imported at the WRONG base makes every
#     pointer constant resolve to the wrong (often empty/string) address, so
#     the analyzer never forms data references. Import each binary at the base
#     where its own pointer constants are correct and xrefs auto-form.
#
# Usage:
#   ingest-re-bins.sh                 # uses $RE_BINS/ingest.manifest
#   RE_BINS=/opt/re-bins ingest-re-bins.sh
#
# Manifest format (whitespace-separated; '#' comments; blank lines ok):
#   <file>            <language-id>            <base|->     [loader]
# Examples:
#   rtecdc.bin        ARM:LE:32:Cortex         0xed0000     BinaryLoader
#   dhd.ko            AARCH64:LE:64:v8A        -            ElfLoader
#   hmoswp.elf        ARM:LE:32:v8             -            ElfLoader
#   # ram.elf IMAGE-BASE SKEW (see hme_rings_init_set_idma_gate plate comment):
#   # code/data pointer constants are firmware-VA but bytes sit 0x10000 high,
#   # so the dump must be loaded 0x10000 LOWER for constants to resolve.
#   # BinaryLoader can't apply a negative base on a 32-bit space without wrap,
#   # so strip the leading 0x10000 bytes first and load the remainder at 0:
#   #   dd if=ram.elf of=ram.shift.bin bs=1 skip=65536   (or bs=64k skip=1)
#   ram.shift.bin     ARM:LE:32:Cortex         0x0          BinaryLoader
# ---------------------------------------------------------------------------
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
GHIDRA_PROJECT_DIR="${GHIDRA_PROJECT_DIR:-/opt/ghidra-projects/re}"
RE_BINS="${RE_BINS:-/opt/re-bins}"
MANIFEST="${MANIFEST:-$RE_BINS/ingest.manifest}"
HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"

# Project targeting MUST match how the backend opens it: the headless service
# runs `--project $GHIDRA_PROJECT_DIR` and opens the single *.gpr INSIDE that
# directory. analyzeHeadless takes `<location> <name>` and writes
# <location>/<name>.gpr — so location MUST be $GHIDRA_PROJECT_DIR itself (not its
# parent), else the imports land in a sibling project the backend never opens.
PROJ_DIR="$GHIDRA_PROJECT_DIR"
_existing_gpr="$(find "$GHIDRA_PROJECT_DIR" -maxdepth 1 -name '*.gpr' 2>/dev/null | head -1)"
if [ -n "$_existing_gpr" ]; then
  PROJ_NAME="$(basename "$_existing_gpr" .gpr)"   # reuse the project the backend opens
else
  PROJ_NAME="${GHIDRA_PROJECT_NAME:-RE}"
fi
mkdir -p "$PROJ_DIR"

log(){ echo -e "\n\033[1;32m== $* ==\033[0m"; }

[ -x "$HEADLESS" ] || { echo "analyzeHeadless not found at $HEADLESS"; exit 1; }
[ -f "$MANIFEST" ] || { echo "no manifest at $MANIFEST -> nothing to ingest (skip)"; exit 0; }
mkdir -p "$PROJ_DIR"

# Stop the live backend so the project isn't locked during import; the systemd
# unit (Restart=on-failure) will NOT auto-restart on a clean manual stop, so we
# restart it explicitly. A trap guarantees the backend comes back even if a
# single import fails mid-loop (never leave the MCP server down).
restore_backend(){
  if [ "${RESTART_AFTER:-0}" = 1 ]; then
    log "restarting ghidra-headless + bridge"
    systemctl start ghidra-headless ghidra-mcp || true
  fi
}
trap restore_backend EXIT

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ghidra-headless; then
  log "stopping ghidra-headless for exclusive project access"
  systemctl stop ghidra-headless ghidra-mcp || true
  RESTART_AFTER=1
  # clear any stale project lock left by the stopped backend
  rm -f "$GHIDRA_PROJECT_DIR".lock "$GHIDRA_PROJECT_DIR".lock~ \
        "$GHIDRA_PROJECT_DIR"/*.lock "$GHIDRA_PROJECT_DIR"/*.lock~ 2>/dev/null || true
fi

FAILED=""
while read -r FILE LANG BASE LOADER _rest; do
  [ -z "${FILE:-}" ] && continue
  case "$FILE" in \#*) continue;; esac
  LOADER="${LOADER:-BinaryLoader}"
  SRC="$RE_BINS/$FILE"
  [ -f "$SRC" ] || { echo "  ! missing $SRC (skip)"; continue; }

  ARGS=( "$PROJ_DIR" "$PROJ_NAME" -import "$SRC" -overwrite
         -processor "$LANG" -loader "$LOADER" )
  if [ "${BASE:-}" != "-" ] && [ -n "${BASE:-}" ]; then
    ARGS+=( -loader-baseAddr "$BASE" )
  fi
  log "ingest $FILE  ($LANG @ ${BASE:--})"
  # imports, runs default analysis, saves into project; a failure here must not
  # abort the run (set -e) and strand the backend — record and continue.
  if ! "$HEADLESS" "${ARGS[@]}"; then
    echo "  ! ingest FAILED for $FILE"; FAILED="$FAILED $FILE"
  fi
done < "$MANIFEST"

log "ingest complete -> programs persist in project $GHIDRA_PROJECT_DIR"
[ -n "$FAILED" ] && echo "  WARNING: failed imports:$FAILED"
exit 0
