#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Pull remote lib, patch it, push via bind mount, restart camera services.
set -euo pipefail

REMOTE_TMP="/data/local/tmp/mtkcam_raw"
PATCHED="/tmp/libmtkcam_metastore_patched.so"

echo "=== mtkcam-raw live test ==="

# ── Clean any stale mounts first ──────────────────────────────────
echo "[0] Cleaning stale mounts..."
bash "$(cd "$(dirname "$0")" && pwd)/restore.sh" 2>/dev/null || true

# ── Find remote lib (follow symlinks) ────────────────────────────
echo "[1] Locating remote library..."
REMOTE_LINK=$(adb shell "su -c 'find /vendor /system /product -name libmtkcam_metastore.so 2>/dev/null'" | head -1 | tr -d '\r')
if [ -z "$REMOTE_LINK" ]; then
  echo "ERROR: libmtkcam_metastore.so not found on device"
  exit 1
fi
REMOTE_LIB=$(adb shell "su -c 'readlink -f $REMOTE_LINK 2>/dev/null || echo $REMOTE_LINK'" | tr -d '\r')
echo "  Symlink: $REMOTE_LINK"
echo "  Real:    $REMOTE_LIB"

# ── Pull remote lib and patch it ─────────────────────────────────
echo "[2] Pulling remote library..."
adb pull "$REMOTE_LIB" /tmp/remote_lib.so >/dev/null 2>&1

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "[3] Patching..."
python3 -m mtkcam_raw --config "$REPO_DIR/bin/patch.toml" patch /tmp/remote_lib.so -o "$PATCHED" -q 2>&1

# ── Set up tmpfs ─────────────────────────────────────────────────
echo "[4] Setting up tmpfs..."
adb shell "su -c 'mkdir -p $REMOTE_TMP && mount -t tmpfs tmpfs $REMOTE_TMP'"

# ── Push patched lib ─────────────────────────────────────────────
echo "[5] Pushing patched library..."
adb push "$PATCHED" "${REMOTE_TMP}/libmtkcam_metastore.so" >/dev/null 2>&1

# ── Back up and bind mount ───────────────────────────────────────
echo "[6] Backing up original and bind-mounting..."
ORIG_CONTEXT=$(adb shell "su -c 'ls -Z $REMOTE_LIB 2>/dev/null' | awk '{print \$1}' | tr -d '\r'")
adb shell "su -c 'cp $REMOTE_LIB ${REMOTE_TMP}/libmtkcam_metastore.so.orig && chmod 644 ${REMOTE_TMP}/libmtkcam_metastore.so.orig'"
adb shell "su -c 'chcon u:object_r:vendor_file:s0 ${REMOTE_TMP}/libmtkcam_metastore.so'"
adb shell "su -c 'mount -o bind ${REMOTE_TMP}/libmtkcam_metastore.so $REMOTE_LIB'"
echo "  [OK] Bind mount active"

# ── Restart camera services ──────────────────────────────────────
echo "[7] Restarting camera services..."
adb shell "su -c 'setprop ctl.stop camerahalserver && setprop ctl.stop cameraserver && sleep 1 && setprop ctl.start cameraserver && setprop ctl.start camerahalserver'"
echo "  [OK] camerahalserver + cameraserver restarted"

echo
echo "=== DONE ==="
echo "To restore: bash bin/restore.sh"
