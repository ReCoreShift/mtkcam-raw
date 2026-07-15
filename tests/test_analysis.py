# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for analysis module.


Runs against the actual libmtkcam_metastore.so binary.
"""

# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


import os
import struct
import pytest
from mtkcam_raw.elf import parse_elf
from mtkcam_raw.analysis import (
    find_all_stream_hooks,
    analyze_all_capabilities,
)

BINARY = os.environ.get("TEST_BINARY")
if BINARY is None:
    for candidate in ("libmtkcam_metastore.so", "bin/libmtkcam_metastore.so"):
        if os.path.exists(candidate):
            BINARY = candidate
            break
if BINARY is None:
    BINARY = "/tmp/libmtkcam_metastore_original.so"


@pytest.fixture(scope="module")
def image():
    with open(BINARY, "rb") as f:
        data = f.read()
    return parse_elf(data)


class TestFindCapabilityBlocks:
    def test_all_blocks(self, image):
        blocks = analyze_all_capabilities(image)
        assert len(blocks) > 0
        s5kjn1 = [b for b in blocks if "S5KJN1" in b.sensor_name]
        assert len(s5kjn1) >= 1

    def test_s5kjn1_properties(self, image):
        blocks = analyze_all_capabilities(image)
        s5kjn1 = [b for b in blocks if "S5KJN1" in b.sensor_name][0]
        assert s5kjn1.function_va == 0x3f594
        assert len(s5kjn1.slots) >= 6
        values = s5kjn1.values
        assert 0 in values  # BACKWARD_COMPATIBLE
        assert 1 in values  # MANUAL_SENSOR
        assert 2 in values  # MANUAL_POST_PROCESSING
        assert 5 in values  # BURST_CAPTURE
        assert 6 in values  # READ_SENSOR_SETTINGS
        assert 9 in values  # HIGH_SPEED_VIDEO
        assert 3 not in values  # RAW not present

    def test_slot_movz_instructions(self, image):
        blocks = analyze_all_capabilities(image)
        s5kjn1 = [b for b in blocks if "S5KJN1" in b.sensor_name][0]
        for slot in s5kjn1.slots:
            if slot.value == 0:
                # slot value 0 uses strb wzr, not movz
                insn = struct.unpack("<I", image.data[slot.file_offset : slot.file_offset + 4])[0]
                assert insn & 0xFF000000 == 0x39000000, \
                    f"slot 0x{slot.file_offset:x}: expected strb, got 0x{insn:08x}"
            else:
                insn = struct.unpack("<I", image.data[slot.file_offset : slot.file_offset + 4])[0]
                assert insn & 0xFF000000 == 0x52000000, \
                    f"slot 0x{slot.file_offset:x}: expected movz, got 0x{insn:08x}"


class TestFindStreamHooks:
    def test_finds_all_hooks(self, image):
        hooks = find_all_stream_hooks(image)
        assert len(hooks) == 48

    def test_s5kjn1_properties(self, image):
        hooks = find_all_stream_hooks(image)
        s5kjn1 = [h for h in hooks if "S5KJN1" in h.sensor_name]
        assert len(s5kjn1) >= 1
        hook = s5kjn1[0]
        assert hook.function_va == 0x3f594
        assert hook.hook_va == 0x3f9f8

    def test_hook_is_bl(self, image):
        hooks = find_all_stream_hooks(image)
        s5kjn1 = [h for h in hooks if "S5KJN1" in h.sensor_name][0]
        insn = struct.unpack("<I", image.data[s5kjn1.entry_for_call_offset : s5kjn1.entry_for_call_offset + 4])[0]
        assert insn >> 26 == 0x25, f"Expected BL encoding, got 0x{insn:08x}"
