#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
REPORT_FILE=""
VERIFY_LOG=""

# ── Utilities ──────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
ok()   { echo "  [OK] $*"; }

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] <device> [stage]

Stages: validate | patch | verify | package | all (default)

Options:
  --config FILE   TOML config (default: auto-detect from device name)
  --out DIR       Output directory (default: $OUT_DIR)
  --lib FILE      Override input library path
  --list          List supported devices and exit
  --help          Show this help

Examples:
  $(basename "$0") --list
  $(basename "$0") INOI_A75 all
  $(basename "$0") ADVAN_X1 patch
EOF
  exit 0
}

# ── Config resolution ──────────────────────────────────────────────

resolve_config() {
  local dev="$1"
  local dev_lc="${dev,,}"
  # Try exact, then lowercased, then fallback default
  for candidate in \
    "$SCRIPT_DIR/bin/patch.${dev}.toml" \
    "$SCRIPT_DIR/bin/patch.${dev_lc}.toml" \
    "$SCRIPT_DIR/bin/patch_${dev}.toml" \
    "$SCRIPT_DIR/bin/patch_${dev_lc}.toml" \
    "$SCRIPT_DIR/configs/${dev}.toml" \
    "$SCRIPT_DIR/configs/${dev_lc}.toml"; do
    if [ -f "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

resolve_lib() {
  local dev="$1"
  local dev_upper="${dev^^}"
  # Replace hyphens with underscores for variable matching
  local dev_var="${dev_upper//-/_}"
  # Check for device-specific binary
  for candidate in \
    "$SCRIPT_DIR/${dev_var}_libmtkcam_metastore.so" \
    "$SCRIPT_DIR/${dev}_libmtkcam_metastore.so" \
    "$SCRIPT_DIR/bin/libmtkcam_metastore.so"; do
    if [ -f "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

# ── Device listing ─────────────────────────────────────────────────

list_devices() {
  info "Supported devices:"
  python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR/src')
from mtkcam_raw.devices import DEVICES
for name in sorted(DEVICES):
    dev = DEVICES[name]
    print(f'  {name}  ({dev.soc})')
"
}

# ── Stage implementations ──────────────────────────────────────────

stage_validate() {
  local dev="$1" config="$2" lib="$3"
  info "validate: $dev"
  python3 -m mtkcam_raw \
    --device "$dev" \
    --config "$config" \
    validate "$lib" 2>&1 | tee -a "$VERIFY_LOG" || die "Validation failed"
  ok "validation passed"
}

stage_patch() {
  local dev="$1" config="$2" lib="$3"
  local out_so="$OUT_DIR/$dev/libmtkcam_metastore.patched.so"
  mkdir -p "$(dirname "$out_so")"
  info "patch: $dev -> $out_so"
  python3 -m mtkcam_raw \
    --device "$dev" \
    --config "$config" \
    patch "$lib" -o "$out_so" --validate 2>&1 | tee -a "$VERIFY_LOG" || die "Patch failed"
  ok "patched -> $out_so"
}

stage_verify() {
  local dev="$1" lib="$2"
  local out_so="$OUT_DIR/$dev/libmtkcam_metastore.patched.so"
  if [ ! -f "$out_so" ]; then
    die "No patched binary found at $out_so — run patch stage first"
  fi
  info "verify: $dev"
  python3 -m mtkcam_raw verify "$lib" "$out_so" 2>&1 | tee -a "$VERIFY_LOG" || die "Verification failed"
  ok "verification complete"
}

stage_package() {
  local dev="$1" config="$2" lib="$3"
  local dir="$OUT_DIR/$dev"
  local out_so="$dir/libmtkcam_metastore.patched.so"
  if [ ! -f "$out_so" ]; then
    die "No patched binary at $out_so — run patch stage first"
  fi

  # Gather metadata
  local patch_count patch_version
  patch_count=$(grep -c "redirect" "$VERIFY_LOG" 2>/dev/null || echo 0)
  patch_version=$(grep "patch_version" <<<"$(python3 -c "
import sys; sys.path.insert(0, '$SCRIPT_DIR/src')
from mtkcam_raw.devices import get_device
d = get_device('$dev')
print(d.patches.patch_version)
")" 2>/dev/null || echo "unknown")

  local in_sha out_sha
  in_sha=$(sha256sum "$lib" 2>/dev/null | awk '{print $1}')
  out_sha=$(sha256sum "$out_so" 2>/dev/null | awk '{print $1}')

  # metadata.toml
  cat > "$dir/metadata.toml" <<TOMLEOF
[device]
name = "$dev"
soc = "$dev"
patch_version = "$patch_version"
config = "$config"

[checksums]
input = "$in_sha"
output = "$out_sha"

[patch]
records = $patch_count
TOMLEOF
  ok "metadata written to $dir/metadata.toml"

  # report.json
  python3 -c "
import json
out = {
    'device': '$dev',
    'patch_version': '$patch_version',
    'patch_count': $patch_count,
    'checksums': {'input': '$in_sha', 'output': '$out_sha'},
}
with open('$dir/report.json', 'w') as f:
    json.dump(out, f, indent=2)
" 2>/dev/null || true
  ok "report written to $dir/report.json"
  ok "package complete: $dir/"
}

# ── Main ───────────────────────────────────────────────────────────

STAGES="validate patch verify package"
CMD_CONFIG=""
CMD_LIB=""
CMD_OUT_DIR="$OUT_DIR"
DEVICE=""
STAGE="all"

# Parse options
while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) list_devices; exit 0 ;;
    --help|-h) usage ;;
    --config) shift; CMD_CONFIG="$1"; shift ;;
    --out)    shift; CMD_OUT_DIR="$1"; shift ;;
    --lib)    shift; CMD_LIB="$1"; shift ;;
    -*)
      # If it doesn't look like a device name (no uppercase prefix), error
      if [[ "$1" =~ ^--? ]]; then
        die "Unknown option: $1"
      fi
      break
      ;;
    *)
      # First non-option argument is device
      if [ -z "$DEVICE" ]; then
        DEVICE="$1"
      elif [ -z "$STAGE" ] || [ "$STAGE" = "all" ]; then
        STAGE="$1"
      else
        die "Unexpected argument: $1"
      fi
      shift
      ;;
  esac
done

if [ -z "$DEVICE" ]; then
  usage
fi

# Normalise device name
DEVICE="${DEVICE^^}"
DEVICE="${DEVICE//-/_}"

# Resolve config
if [ -n "$CMD_CONFIG" ]; then
  CONFIG="$CMD_CONFIG"
else
  CONFIG=$(resolve_config "$DEVICE") || die "No config found for device $DEVICE"
fi
info "config: $CONFIG"

# Resolve library
if [ -n "$CMD_LIB" ]; then
  LIB="$CMD_LIB"
else
  LIB=$(resolve_lib "$DEVICE") || die "No library found for device $DEVICE — place it at bin/libmtkcam_metastore.so or pass --lib"
fi
info "library: $LIB"

# Ensure library exists
[ -f "$LIB" ] || die "Library not found: $LIB"

# Override OUT_DIR if --out was passed
[ -n "$CMD_OUT_DIR" ] && OUT_DIR="$CMD_OUT_DIR"

# Set up output paths
mkdir -p "$OUT_DIR/$DEVICE"
REPORT_FILE="$OUT_DIR/$DEVICE/report.json"
VERIFY_LOG="$OUT_DIR/$DEVICE/verify.log"
# Clear verify log for fresh run
: > "$VERIFY_LOG"

case "$STAGE" in
  all)
    for s in $STAGES; do
      "stage_$s" "$DEVICE" "$CONFIG" "$LIB"
    done
    ;;
  validate|patch|verify|package)
    "stage_$STAGE" "$DEVICE" "$CONFIG" "$LIB"
    ;;
  *)
    die "Unknown stage: $STAGE. Valid: $STAGES all"
    ;;
esac

echo
echo "=== $DEVICE:$STAGE complete ==="
