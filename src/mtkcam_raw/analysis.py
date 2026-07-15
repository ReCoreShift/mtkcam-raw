# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Binary analysis — find capability blocks, stream config blocks,
and patch sites structurally.
"""

# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from mtkcam_raw.aarch64 import (
    MOV_W1_C000C,
    MOVK_W1_BASE,
    STRB_W8_SP,
    STRBWZR_SP16,
    SUB_X0_X29_0x50,
    ADD_X1_SP_0x10,
    read_word,
    decode_movz_w8,
    decode_exact_bl,
    decode_branch_target,
)
from mtkcam_raw.elf import ElfImage
from mtkcam_raw.metadata import (
    TAG_AVAILABLE_STREAM_CONFIGURATIONS,
)


@dataclass
class CapabilitySlot:
    """One capability value push site (movz + strb + sub + add + bl)."""
    file_offset: int       # of the movz instruction
    value: int
    bl_push_back_offset: int  # file offset of the bl push_back instruction
    push_back_target_va: Optional[int]  # VA target of the bl, if decodable

    def get_function_va(self) -> Optional[int]:
        """Return the function VA this slot belongs to (needs context)."""
        return None


@dataclass
class CapabilityBlock:
    """A sensor's capability initialisation block (tag 0xc000c)."""
    sensor_name: str
    function_va: int
    function_size: int
    tag_file_offset: int       # mov w1, #0xc000c
    entry_for_call_offset: int  # bl entryFor
    slots: list[CapabilitySlot] = field(default_factory=list)

    @property
    def values(self) -> list[int]:
        return [s.value for s in self.slots]


@dataclass
class StreamBlock:
    """A sensor's stream configuration block (tag 0xd0012)."""
    sensor_name: str
    function_va: int
    tag_file_offset: int       # movk w1, #0xd, lsl #16
    entry_for_call_offset: int  # bl entryFor  (file offset)
    hook_va: int               # VA of the bl entryFor call
    push_long_target_va: Optional[int] = None  # decoded BL target (push_long helper)


@dataclass
class BinaryProfile:
    """Discovered or validated helper function addresses in the binary."""
    entry_for_va: int    # entryFor helper (called at start of metadata init)
    push_long_va: int    # push_long helper (called for each field append)


def discover_binary_profile(image: ElfImage) -> BinaryProfile:
    """
    Discover entry_for_va and push_long_va from the binary by
    scanning sensor stream-config functions.
    """
    hooks = find_all_stream_hooks(image)
    if not hooks:
        raise ValueError("No stream hooks found; cannot discover helpers")

    # push_long_va comes from the BL at the hook site
    hook = hooks[0]
    # The BL at the hook site calls entryFor to initialise a
    # metadata entry.  Decode its target → entry_for_va.
    entry_for_word = struct.unpack("<I",
        image.data[hook.entry_for_call_offset:
                   hook.entry_for_call_offset + 4])[0]
    if entry_for_word >> 26 != 0b100101:
        raise ValueError(
            f"Hook at 0x{hook.hook_va:x} is not a BL instruction"
        )
    imm26 = entry_for_word & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    entry_for_va = hook.hook_va + imm26 * 4

    # Discover push_long_va by scanning forward from the hook site
    # for the next BL (which pushes the first field value).
    scan_start = hook.entry_for_call_offset + 4
    scan_end = min(scan_start + 0x100, len(image.data))
    push_long_va = 0
    for off in range(scan_start, scan_end):
        w = struct.unpack_from("<I", image.data, off)[0]
        if w >> 26 == 0b100101:
            t = decode_branch_target(image.data, off, image)
            if t is not None and t != entry_for_va:
                push_long_va = t
                break

    if not push_long_va:
        raise ValueError("Could not discover push_long_va from binary")

    return BinaryProfile(entry_for_va=entry_for_va,
                         push_long_va=push_long_va)


@dataclass
class PatchSite:
    """A detected potential patch site with context."""
    kind: str                  # "capability" or "stream"
    sensor_name: str
    function_va: int
    file_offset: int           # offset of the instruction to modify


def find_capability_block(
    image: ElfImage,
    func_va: int,
    func_size: int,
) -> Optional[CapabilityBlock]:
    """
    Within a sensor constructor function, find the 0xc000c
    capability block and return structured info.
    """
    func_off = image.va_to_offset(func_va)
    if func_off is None:
        return None

    scan_size = func_size if func_size > 0 else 0x800
    body = image.data[func_off : func_off + scan_size]

    tag_pattern = struct.pack("<I", MOV_W1_C000C)
    tag_pos = body.find(tag_pattern)
    if tag_pos < 0:
        return None

    tag_file_off = func_off + tag_pos
    entry_for_off = tag_file_off + 4  # instruction after mov

    slots: list[CapabilitySlot] = []
    i = tag_pos + 4
    end = min(len(body), tag_pos + 0x100)

    IMM_MASK = 0xFFC003FF  # mask off imm12 for strb/sub/add comparisons
    STRB_W8_BASE = STRB_W8_SP  # strb w8, [sp] with imm12=0
    STRB_WZR_BASE = STRBWZR_SP16 & IMM_MASK  # strb wzr, [sp] with imm12=0
    SUB_X0_X29_BASE = SUB_X0_X29_0x50 & IMM_MASK
    ADD_X1_SP_BASE = ADD_X1_SP_0x10 & IMM_MASK

    while i < end - 4:
        w = read_word(body, i)

        # Value-0 slot: strb wzr, [sp, #N]; sub x0, x29, #0x50; add x1, sp, #0x10; bl push_back
        if (w & IMM_MASK) == STRB_WZR_BASE:
            w4 = read_word(body, i + 4)
            w8 = read_word(body, i + 8)
            if (
                i + 12 < end
                and (w4 & IMM_MASK) == SUB_X0_X29_BASE
                and (w8 & IMM_MASK) == ADD_X1_SP_BASE
            ):
                bl_off = func_off + i + 12
                bl_target = decode_exact_bl(
                    image.data, bl_off, image
                )
                slots.append(CapabilitySlot(
                    file_offset=func_off + i,
                    value=0,
                    bl_push_back_offset=bl_off,
                    push_back_target_va=bl_target,
                ))
                i += 16
                continue

        # Non-zero slot: movz w8, #N; strb w8, [sp, #0x10]; sub x0, x29, #0x50; add x1, sp, #0x10; bl push_back
        n = decode_movz_w8(body[i : i + 4])
        if n is not None:
            if i + 4 < end:
                w4 = read_word(body, i + 4)
                if (w4 & IMM_MASK) == STRB_W8_BASE:
                    w8 = read_word(body, i + 8)
                    w12 = read_word(body, i + 12)
                    if (
                        i + 12 < end
                        and (w8 & IMM_MASK) == SUB_X0_X29_BASE
                        and (w12 & IMM_MASK) == ADD_X1_SP_BASE
                    ):
                        bl_off = func_off + i + 16
                        bl_target = decode_exact_bl(
                            image.data, bl_off, image
                        )
                        slots.append(CapabilitySlot(
                            file_offset=func_off + i,
                            value=n,
                            bl_push_back_offset=bl_off,
                            push_back_target_va=bl_target,
                        ))
                        i += 20
                        continue

        # After the last slot, the next instruction is usually SUB_X0_X29_0x50
        # which starts tag_processing. Stop scanning there.
        if (w & IMM_MASK) == SUB_X0_X29_BASE and len(slots) > 0:
            break

        i += 4

    if not slots:
        return None

    return CapabilityBlock(
        sensor_name="",
        function_va=func_va,
        function_size=func_size,
        tag_file_offset=tag_file_off,
        entry_for_call_offset=entry_for_off,
        slots=slots,
    )


def find_stream_block(
    image: ElfImage,
    func_va: int,
    func_size: int,
    hook_va: int,
) -> Optional[StreamBlock]:
    """
    Find a tag-0xd0012 block near the given hook VA
    and return structured info.
    """
    func_off = image.va_to_offset(func_va)
    if func_off is None:
        return None

    hook_off = image.va_to_offset(hook_va)
    if hook_off is None:
        return None

    return StreamBlock(
        sensor_name="",
        function_va=func_va,
        tag_file_offset=hook_off - 8,
        entry_for_call_offset=hook_off,
        hook_va=hook_va,
    )


SENSOR_PREFIX = (
    "constructCustStaticMetadata_PLATFORM_PROJECT_SENSOR_DRVNAME_"
)


def find_sensor_symbols(image: ElfImage) -> list:
    return [
        s for s in image.symbols
        if s.name.startswith(SENSOR_PREFIX)
    ]


def analyze_all_capabilities(
    image: ElfImage,
) -> list[CapabilityBlock]:
    """Scan all sensor functions for capability blocks."""
    results: list[CapabilityBlock] = []
    for sym in find_sensor_symbols(image):
        block = find_capability_block(
            image, sym.value, sym.size
        )
        if block is not None:
            from mtkcam_raw.metadata import sensor_short_name
            block.sensor_name = sensor_short_name(sym.name)
            results.append(block)
    return results


def find_all_stream_hooks(
    image: ElfImage,
) -> list[StreamBlock]:
    """
    Find all tag-0xd0012 (stream config) entryFor call sites
    across sensor functions.
    """
    TAG_STREAM = TAG_AVAILABLE_STREAM_CONFIGURATIONS
    tag_lo = TAG_STREAM & 0xFFFF
    tag_hi_shifted = (TAG_STREAM >> 16) & 0xFFFF

    results: list[StreamBlock] = []
    for sym in find_sensor_symbols(image):
        func_off = image.va_to_offset(sym.value)
        if func_off is None:
            continue
        scan_size = sym.size if sym.size > 0 else 0x800
        body = image.data[func_off : func_off + scan_size]

        # Pattern: mov w1, #tag_lo; movk w1, #tag_hi, lsl #16; bl entryFor
        movk_pattern = struct.pack(
            "<I", MOVK_W1_BASE | ((tag_hi_shifted & 0xFFFF) << 5) | (1 << 21)
        )

        pos = 0
        while pos < len(body) - 12:
            w = read_word(body, pos)
            if (w & 0xFFE0001F) == 0x52800001:  # movz w1, #N
                if (w >> 5) & 0xFFFF == tag_lo:
                    # Check for movk + bl after it
                    if pos + 8 < len(body):
                        w2 = read_word(body, pos + 4)
                        if w2 == struct.unpack(
                            "<I", movk_pattern
                        )[0]:
                            w3 = read_word(body, pos + 8)
                            if (w3 >> 26) == 0b100101:  # BL
                                hook_va = sym.value + pos + 8
                                push_long_target = decode_branch_target(
                                    image.data, func_off + pos + 8, image
                                )
                                from mtkcam_raw.metadata import sensor_short_name
                                name = sensor_short_name(sym.name)
                                block = StreamBlock(
                                    sensor_name=name,
                                    function_va=sym.value,
                                    tag_file_offset=func_off + pos,
                                    entry_for_call_offset=func_off + pos + 8,
                                    hook_va=hook_va,
                                    push_long_target_va=push_long_target,
                                )
                                results.append(block)
                                break
                pos += 4
            else:
                pos += 4

    return results
