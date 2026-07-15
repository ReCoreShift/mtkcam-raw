#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Aggressively clean all bind mounts, restore original, restart camera services.
set -euo pipefail

echo "=== Restoring original library ==="

REMOTE_LINK=$(adb shell "su -c 'find /vendor /system /product -name libmtkcam_metastore.so 2>/dev/null'" | head -1 | tr -d '\r')
REMOTE_LIB=$(adb shell "su -c 'readlink -f $REMOTE_LINK 2>/dev/null || echo $REMOTE_LINK'" | tr -d '\r')

echo "  Stopping camera services..."
adb shell "su -c 'setprop ctl.stop camerahalserver; setprop ctl.stop cameraserver; sleep 1'"

echo "  Unmounting stale bind mounts..."
adb shell 'su -c "mount | grep mtkcam | while read a b c d; do umount -l \"$c\" 2>/dev/null || true; done"'

echo "  Verifying clean..."
STILL=$(adb shell "su -c 'mount | grep mtkcam || true'" 2>/dev/null)
if [ -n "$STILL" ]; then
  echo "  WARNING: $STILL"
  adb shell 'su -c "mount | grep mtkcam | while read a b c d; do umount -l \"$c\" 2>/dev/null || true; done"'
fi

echo "  Restarting camera services..."
adb shell "su -c 'setprop ctl.start cameraserver; setprop ctl.start camerahalserver'"
echo "  [OK] All mounts cleaned, camera services restarted"
