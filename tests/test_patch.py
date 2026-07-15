# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for patch module."""

# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.



import os
import struct
import pytest
from mtkcam_raw.elf import parse_elf
from mtkcam_raw.cave import find_plt_cave, find_load12_gap, find_load2_end_extension, CaveAllocator
from mtkcam_raw.patch import apply_patches
from mtkcam_raw.trampoline import (
    make_capability_append_patches,
    make_stream_append_patches,
)
from mtkcam_raw.analysis import (
    analyze_all_capabilities,
    find_all_stream_hooks,
    BinaryProfile,
)
from mtkcam_raw.aarch64 import decode_branch_target

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


class TestFindCaves:
    def test_plt_cave(self, image):
        cave = find_plt_cave(image)
        assert cave is not None
        assert cave.size == 44
        assert cave.file_offset == 0xab064

    def test_load_gap_cave(self, image):
        cave = find_load12_gap(image)
        assert cave is not None
        assert cave.file_offset == 0x263cc
        assert cave.size == 3124
        assert cave.extend_load is True
        assert cave.is_gap is True

    def test_load_end_cave(self, image):
        cave = find_load2_end_extension(image)
        assert cave is not None
        assert cave.file_offset == 0xabb50
        assert cave.size == 0x4b1
        assert cave.extend_load is True
        assert cave.is_gap is False

    def test_caves_different(self, image):
        plt_cave = find_plt_cave(image)
        gap_cave = find_load12_gap(image)
        end_cave = find_load2_end_extension(image)
        assert plt_cave.file_offset != gap_cave.file_offset
        assert gap_cave.file_offset != end_cave.file_offset


class TestMakeCapabilityPatches:
    def test_s5kjn1_raw_append(self, image):
        blocks = analyze_all_capabilities(image)
        s5kjn1 = [b for b in blocks if "S5KJN1" in b.sensor_name][0]
        allocator = CaveAllocator.from_image(image)

        last_slot = s5kjn1.slots[-1]
        assert last_slot.push_back_target_va is not None

        patches = make_capability_append_patches(
            image, last_slot.file_offset, [3],
            last_slot.push_back_target_va, allocator,
        )
        assert len(patches) >= 2

    def test_preserves_existing_cap(self, image):
        blocks = analyze_all_capabilities(image)
        s5kjn1 = [b for b in blocks if "S5KJN1" in b.sensor_name][0]
        allocator = CaveAllocator.from_image(image)
        last_slot = s5kjn1.slots[-1]

        patches = make_capability_append_patches(
            image, last_slot.file_offset, [3],
            last_slot.push_back_target_va, allocator,
        )
        data = bytearray(image.data)
        result = apply_patches(data, patches)
        assert result.is_valid

        # Original slot value preserved (movz instruction unchanged)
        original_val = struct.unpack("<I", image.data[last_slot.file_offset:last_slot.file_offset+4])[0]
        patched_val = struct.unpack("<I", data[last_slot.file_offset:last_slot.file_offset+4])[0]
        assert original_val == patched_val


class TestMakeStreamPatches:
    def test_s5kjn1_stream_append(self, image):
        hooks = find_all_stream_hooks(image)
        s5kjn1 = [h for h in hooks if "S5KJN1" in h.sensor_name][0]
        allocator = CaveAllocator.from_image(image)

        profile = BinaryProfile(
            entry_for_va=0xAB0A0,
            push_long_va=0xAB190,
        )
        entries = [(32, 0xFF0, 0xC00, 0, 0x3F940AA, 0x1FCA055)]

        patches = make_stream_append_patches(
            image, s5kjn1.hook_va, profile, allocator, entries,
        )
        assert len(patches) >= 2

        data = bytearray(image.data)
        result = apply_patches(data, patches)
        assert result.is_valid

        # Verify hook redirect was changed
        old_bl = struct.unpack("<I", image.data[s5kjn1.entry_for_call_offset:s5kjn1.entry_for_call_offset+4])[0]
        new_bl = struct.unpack("<I", data[s5kjn1.entry_for_call_offset:s5kjn1.entry_for_call_offset+4])[0]
        assert old_bl != new_bl, "hook BL was not redirected"

        target = decode_branch_target(data, s5kjn1.entry_for_call_offset, image)
        assert target is not None

    def test_multiple_entries(self, image):
        hooks = find_all_stream_hooks(image)
        s5kjn1 = [h for h in hooks if "S5KJN1" in h.sensor_name][0]
        allocator = CaveAllocator.from_image(image)

        profile = BinaryProfile(
            entry_for_va=0xAB0A0,
            push_long_va=0xAB190,
        )
        entries = [
            (32, 0xFF0, 0xC00, 0, 0x3F940AA, 0x1FCA055),
            (32, 0xCC0, 0x990, 0, 0x3F940AA, 0x1FCA055),
        ]

        patches = make_stream_append_patches(
            image, s5kjn1.hook_va, profile, allocator, entries,
        )
        data = bytearray(image.data)
        result = apply_patches(data, patches)
        assert result.is_valid
