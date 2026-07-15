# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for ELF parsing and VA translation."""


import struct
import pytest
from mtkcam_raw.elf import parse_elf, ProgramHeader


def _minimal_elf64_le() -> bytes:
    """Build a minimal 64-bit little-endian ELF with one PT_LOAD."""

# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

    data = bytearray(128)
    data[0:4] = b"\x7fELF"
    data[4:8] = b"\x02\x01\x01\x00"
    # e_type = 3 (shared), e_machine = 0x3E (AArch64)
    struct.pack_into("<H", data, 0x10, 3)
    struct.pack_into("<H", data, 0x12, 0x3E)
    struct.pack_into("<Q", data, 0x20, 0x40)  # e_phoff
    struct.pack_into("<Q", data, 0x28, 0)  # e_shoff = 0
    struct.pack_into("<H", data, 0x36, 56)  # e_phentsize
    struct.pack_into("<H", data, 0x38, 1)  # e_phnum
    struct.pack_into("<H", data, 0x3A, 0)  # e_shentsize
    struct.pack_into("<H", data, 0x3C, 0)  # e_shnum
    struct.pack_into("<H", data, 0x3E, 0)  # e_shstrndx

    # PT_LOAD: R-X at VA 0x1000, offset 0x200
    struct.pack_into("<I", data, 0x40, 1)  # p_type = PT_LOAD
    struct.pack_into("<I", data, 0x44, 5)  # p_flags = R+E
    struct.pack_into("<Q", data, 0x48, 0x200)  # p_offset
    struct.pack_into("<Q", data, 0x50, 0x1000)  # p_vaddr
    struct.pack_into("<Q", data, 0x58, 0x1000)  # p_paddr
    struct.pack_into("<Q", data, 0x60, 0x100)  # p_filesz
    struct.pack_into("<Q", data, 0x68, 0x100)  # p_memsz
    struct.pack_into("<Q", data, 0x70, 0x1000)  # p_align

    return bytes(data)


class TestElfParsing:
    def test_invalid_magic(self):
        with pytest.raises(ValueError, match="Not an ELF"):
            parse_elf(b"\x00" * 64)

    def test_not_64bit(self):
        data = bytearray(b"\x7fELF" + b"\x01" + b"\x00" * 59)
        with pytest.raises(ValueError, match="64-bit"):
            parse_elf(bytes(data))

    def test_minimal_elf(self):
        elf = _minimal_elf64_le()
        image = parse_elf(elf)
        assert len(image.phdrs) == 1
        assert image.phdrs[0].is_load
        assert image.phdrs[0].is_executable

    def test_va_to_offset(self):
        elf = _minimal_elf64_le()
        image = parse_elf(elf)
        ph = image.phdrs[0]
        assert image.va_to_offset(ph.p_vaddr) == ph.p_offset
        assert image.va_to_offset(ph.p_vaddr + 0x50) == ph.p_offset + 0x50
        assert image.va_to_offset(0x0) is None
        assert image.va_to_offset(0xFFFFFF) is None

    def test_offset_to_va(self):
        elf = _minimal_elf64_le()
        image = parse_elf(elf)
        ph = image.phdrs[0]
        assert image.offset_to_va(ph.p_offset) == ph.p_vaddr
        assert image.offset_to_va(ph.p_offset + 0x30) == ph.p_vaddr + 0x30
        assert image.offset_to_va(0x0) is None

    def test_sha256(self):
        elf = _minimal_elf64_le()
        image = parse_elf(elf)
        assert len(image.sha256) == 64
        assert all(c in "0123456789abcdef" for c in image.sha256)


class TestElfImageProperties:
    def test_load_segments(self):
        elf = _minimal_elf64_le()
        image = parse_elf(elf)
        assert len(image.load_segments) == 1

    def test_executable_load(self):
        elf = _minimal_elf64_le()
        image = parse_elf(elf)
        assert image.executable_load is not None
        assert image.executable_load.is_executable

    def test_flags_str(self):
        ph = ProgramHeader(
            index=0, p_type=1, p_flags=5,
            p_offset=0, p_vaddr=0, p_paddr=0,
            p_filesz=0, p_memsz=0, p_align=0,
        )
        assert ph.flags_str == "RE"
        assert ph.is_executable
        assert ph.is_load
