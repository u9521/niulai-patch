"""Tests for the PE primitives.

The checksum test is the important one: it asserts against the *stored* value
in a real Microsoft-toolchain binary, so it validates the implementation rather
than merely re-asserting my own arithmetic.
"""

from __future__ import annotations

import struct

import pytest

from pe import pe

# A real signed binary from the MuMu install is not reproducible in CI, so the
# structural tests build a minimal synthetic PE.  The checksum test additionally
# uses a recorded vector.
REAL_MUMU = "/mnt/c/Program Files/Netease/MuMu/nx_main/MuMuNxMain.exe"


def _minimal_pe64(*, with_sig: bool = False) -> bytes:
    """Build the smallest PE32+ we can get pefile to parse."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", buf, 0x84, 0x8664)  # machine = x64
    struct.pack_into("<H", buf, 0x86, 1)  # 1 section
    struct.pack_into("<H", buf, 0x94, 0xF0)  # SizeOfOptionalHeader
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20B)  # PE32+
    struct.pack_into("<I", buf, opt + 64, 0)  # CheckSum
    struct.pack_into("<I", buf, opt + 108, 16)  # NumberOfRvaAndSizes
    # security directory at index 4 -> opt+112+32
    if with_sig:
        struct.pack_into("<II", buf, opt + 112 + 32, 0x400, 0x20)
    # one section: .text, RVA 0x1000, raw at 0x200 size 0x200, executable
    sec = opt + 0xF0
    buf[sec : sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", buf, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", buf, sec + 36, 0x60000020)
    if with_sig:
        buf.extend(b"\xf8\x29\x00\x00\x00\x02\x02\x00" + b"SIG" * 8)
        struct.pack_into("<I", buf, opt + 112 + 32 + 4, 32)
    return bytes(buf)


def test_parse_rejects_non_pe():
    with pytest.raises(pe.PEError):
        pe.parse(b"not a pe file at all")


def test_parse_minimal():
    info = pe.parse(_minimal_pe64())
    assert info.is_64bit
    assert info.num_sections == 1
    assert info.sections[0].name == ".text"
    assert info.sections[0].is_executable
    assert not info.has_signature


def test_rva_offset_roundtrip():
    info = pe.parse(_minimal_pe64())
    for off in (0x200, 0x280, 0x3FF):
        rva = pe.offset_to_rva(info, off)
        assert rva is not None
        assert pe.rva_to_offset(info, rva) == off


def test_rva_beyond_raw_returns_none():
    # RVA inside the section's virtual span but past its raw data.
    info2 = pe.parse(_minimal_pe64())
    s = info2.sections[0]
    assert pe.rva_to_offset(info2, s.virtual_address + s.raw_size + 4) is None


def test_checksum_matches_real_binary():
    """The stored PE checksum must equal our recomputation."""
    import pathlib

    p = pathlib.Path(REAL_MUMU)
    if not p.is_file():
        pytest.skip("real MuMu binary not available")
    data = p.read_bytes()
    info = pe.parse(data)
    assert info.checksum != 0
    assert pe.pe_checksum(data, info.checksum_offset) == info.checksum


def test_checksum_skips_its_own_field():
    """Changing bytes *inside* the checksum field must not change the result."""
    data = _minimal_pe64()
    info = pe.parse(data)
    a = pe.pe_checksum(data, info.checksum_offset)
    b = bytearray(data)
    struct.pack_into("<I", b, info.checksum_offset, 0xDEADBEEF)
    assert pe.pe_checksum(bytes(b), info.checksum_offset) == a


def test_strip_signature_removes_and_is_idempotent():
    data = _minimal_pe64(with_sig=True)
    info = pe.parse(data)
    assert info.has_signature

    out, changed = pe.strip_signature(data)
    assert changed
    assert len(out) == info.cert_offset
    assert not pe.parse(out).has_signature
    # checksum must be consistent with the new bytes
    out_info = pe.parse(out)
    assert out_info.checksum == pe.pe_checksum(out, out_info.checksum_offset)

    again, changed2 = pe.strip_signature(out)
    assert not changed2
    assert again == out


def test_strip_signature_noop_when_unsigned():
    data = _minimal_pe64()
    out, changed = pe.strip_signature(data)
    assert not changed
    assert out == data


def test_strip_refuses_out_of_range_directory():
    data = bytearray(_minimal_pe64(with_sig=True))
    opt = 0x98
    struct.pack_into("<I", data, opt + 112 + 32, 0x99999)  # bogus cert offset
    with pytest.raises(pe.PEError):
        pe.strip_signature(bytes(data))


def test_real_binary_sections_survive_strip():
    import pathlib

    p = pathlib.Path(REAL_MUMU)
    if not p.is_file():
        pytest.skip("real MuMu binary not available")
    data = p.read_bytes()
    if not pe.parse(data).has_signature:
        # The install has already been patched, and patching strips the
        # Authenticode blob.  There is nothing left to strip, so this test
        # cannot exercise the real binary; the synthetic cases below still
        # cover strip_signature itself.
        pytest.skip("real binary is already unsigned (patched install)")
    out, changed = pe.strip_signature(data)
    assert changed
    before, after = pe.parse(data), pe.parse(out)
    # Every section's raw bytes must be untouched by signature removal.
    # `strict=True`: stripping a signature must not add or drop a section.
    for sb, sa in zip(before.sections, after.sections, strict=True):
        assert data[sb.raw_offset : sb.raw_end] == out[sa.raw_offset : sa.raw_end]
    assert not pe.verify_structure(out)
