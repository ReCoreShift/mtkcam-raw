#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Apply RAW-enablement patches using the module-based CLI.
set -euo pipefail

cd "$(dirname "$0")/.."

# Resolve input SO: check root, then bin/
INPUT_SO="libmtkcam_metastore.so"
if [ ! -f "$INPUT_SO" ]; then
  INPUT_SO="bin/libmtkcam_metastore.so"
fi

echo "=== patching $INPUT_SO ==="
python3 -m mtkcam_raw \
  --config bin/patch.toml \
  patch "$INPUT_SO" \
  -o /tmp/libmtkcam_metastore_patched.so

echo "=== copying to bin/ ==="
cp /tmp/libmtkcam_metastore_patched.so bin/libmtkcam_metastore.patched.so
echo "  SHA256: $(sha256sum bin/libmtkcam_metastore.patched.so | awk '{print $1}')"
