"""Tests for the signature scanner.

The ambiguity guard is the security-critical part: a signature that matches
more than one place must never silently resolve to "the first one".
"""

from __future__ import annotations

import struct

import pytest

from pe import sigscan

REAL_MUMU = "/mnt/c/Program Files/Netease/MuMu/nx_main/MuMuNxMain.exe"


def _pe_with_text(payload: bytes) -> bytes:
    """Wrap ``payload`` in a minimal PE64 whose .text contains it."""
    raw_size = max(0x200, (len(payload) + 0x1FF) // 0x200 * 0x200)
    buf = bytearray(0x200 + raw_size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", buf, 0x84, 0x8664)
    struct.pack_into("<H", buf, 0x86, 1)
    struct.pack_into("<H", buf, 0x94, 0xF0)
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<I", buf, opt + 108, 16)
    sec = opt + 0xF0
    buf[sec : sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", buf, sec + 8, raw_size, 0x1000, raw_size, 0x200)
    struct.pack_into("<I", buf, sec + 36, 0x60000020)
    buf[0x200 : 0x200 + len(payload)] = payload
    return bytes(buf)


def test_parse_spaced_and_compact_are_equivalent():
    a = sigscan.parse_signature("48 8B ?? C3")
    b = sigscan.parse_signature("488B??C3")
    assert a.tokens == b.tokens
    assert a.length == 4
    assert a.literal_count == 3


def test_parse_single_question_alias():
    assert sigscan.parse_signature("48 ? C3").tokens == (0x48, None, 0xC3)


@pytest.mark.parametrize("bad", ["", "ZZ", "48 8B 1", "??", "? ? ?"])
def test_parse_rejects_malformed(bad):
    with pytest.raises(sigscan.SignatureError):
        sigscan.parse_signature(bad)


def test_describe_roundtrip():
    s = sigscan.parse_signature("48 8B ?? C3")
    assert s.describe() == "48 8B ?? C3"


def test_scan_unique_accepts_single_match():
    data = _pe_with_text(b"\x90" * 16 + bytes.fromhex("488B05DEADBEEF") + b"\x90" * 16)
    m = sigscan.scan_unique(data, sigscan.parse_signature("48 8B 05 DE AD BE EF"))
    assert m.rva == 0x1000 + 16  # 16 NOPs after section start


def test_scan_unique_rejects_multiple_matches():
    body = bytes.fromhex("488B05DEADBEEF")
    data = _pe_with_text(body + b"\x90" * 8 + body)
    with pytest.raises(sigscan.SignatureError, match="ambiguous"):
        sigscan.scan_unique(data, sigscan.parse_signature("48 8B 05 DE AD BE EF"))


def test_scan_unique_rejects_absent():
    data = _pe_with_text(b"\x90" * 64)
    with pytest.raises(sigscan.SignatureError, match="not found"):
        sigscan.scan_unique(data, sigscan.parse_signature("DE AD BE EF"))


def test_wildcards_match_anything():
    data = _pe_with_text(bytes.fromhex("488B05AABBCCDD"))
    m = sigscan.scan_unique(data, sigscan.parse_signature("48 8B 05 ?? ?? ?? ??"))
    assert m.rva == 0x1000


def test_scan_does_not_silently_truncate():
    """A cap must raise, not return a partial list."""
    body = bytes.fromhex("488B05DEADBEEF")
    data = _pe_with_text(body * 10)
    with pytest.raises(sigscan.SignatureError, match="cap reached"):
        sigscan.scan(data, sigscan.parse_signature("48 8B 05 DE AD BE EF"), max_matches=3)
    # And with no cap we see every occurrence.
    assert len(sigscan.scan(data, sigscan.parse_signature("48 8B 05 DE AD BE EF"))) == 10


def test_match_offsets_are_rva_consistent():
    payload = b"\x90" * 32 + bytes.fromhex("554889E5")
    data = _pe_with_text(payload)
    m = sigscan.scan_unique(data, sigscan.parse_signature("55 48 89 E5"))
    from pe import pe

    info = pe.parse(data)
    assert pe.rva_to_offset(info, m.rva) == m.offset


@pytest.mark.skipif(
    not __import__("pathlib").Path(REAL_MUMU).is_file(),
    reason="real MuMu binary not available",
)
def test_real_binary_common_prologues_are_ambiguous():
    """Sanity check against a real binary: generic prologues are not unique."""
    import pathlib

    data = pathlib.Path(REAL_MUMU).read_bytes()
    for pat in ("48 89 5C 24 ?? 57", "48 83 EC 28", "40 53 48 83 EC"):
        sig = sigscan.parse_signature(pat)
        assert len(sigscan.scan(data, sig)) > 1
        with pytest.raises(sigscan.SignatureError):
            sigscan.scan_unique(data, sig)
