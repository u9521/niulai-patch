"""Tests for build-identity detection.

The property that matters is stated as a test rather than a comment: the
fingerprint must be **identical before and after our own patching**, because a
guard that fires on a correctly-patched file would be worse than no guard.
"""

from __future__ import annotations

import struct

import pytest

from pe import buildid, patcher, pe


def _pe_with_text(payload: bytes, *, rdata: bytes = b"") -> bytes:
    """A minimal two-section PE32+ with a .text and an optional .rdata."""
    text_raw = max(0x200, (len(payload) + 0x1FF) // 0x200 * 0x200)
    rdata_raw = (len(rdata) + 0x1FF) // 0x200 * 0x200 if rdata else 0
    buf = bytearray(0x200 + text_raw + rdata_raw)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", buf, 0x84, 0x8664)
    struct.pack_into("<H", buf, 0x86, 2 if rdata else 1)
    struct.pack_into("<I", buf, 0x88, 0x6ABBE81B)  # TimeDateStamp
    struct.pack_into("<H", buf, 0x94, 0xF0)
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<I", buf, opt + 56, 0x1D48000)  # SizeOfImage
    struct.pack_into("<I", buf, opt + 108, 16)
    sec = opt + 0xF0
    buf[sec : sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", buf, sec + 8, text_raw, 0x1000, text_raw, 0x200)
    struct.pack_into("<I", buf, sec + 36, 0x60000020)
    buf[0x200 : 0x200 + len(payload)] = payload
    if rdata:
        o = sec + 40
        buf[o : o + 8] = b".rdata\0\0"
        struct.pack_into(
            "<IIII", buf, o + 8, rdata_raw, 0x1000 + text_raw, rdata_raw, 0x200 + text_raw
        )
        struct.pack_into("<I", buf, o + 36, 0x40000040)
        start = 0x200 + text_raw
        buf[start : start + len(rdata)] = rdata
    return bytes(buf)


# --------------------------------------------------------------------------- #
# header facts
# --------------------------------------------------------------------------- #
def test_parse_reads_timestamp_and_size_of_image():
    data = _pe_with_text(b"\x90" * 16)
    info = pe.parse(data)
    assert info.timestamp == 0x6ABBE81B
    assert info.size_of_image == 0x1D48000


# --------------------------------------------------------------------------- #
# fingerprint
# --------------------------------------------------------------------------- #
def test_fingerprint_is_stable_for_the_same_bytes():
    data = _pe_with_text(b"\x90" * 16, rdata=b"hello\x00")
    assert buildid.fingerprint(data) == buildid.fingerprint(data)


def test_fingerprint_is_16_hex_characters():
    fp = buildid.fingerprint(_pe_with_text(b"\x90" * 16))
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_survives_our_own_patching():
    """The load-bearing property.

    Patching rewrites bytes in ``.text`` only, so the fingerprint must not move.
    If this fails, the guard would report "different build" on a file this very
    tool had just patched correctly.
    """
    payload = bytes.fromhex("488B05DEADBEEF") + b"\x90" * 24
    data = _pe_with_text(payload, rdata=b"mainFaqMenuItem\x00")

    patch = patcher.Patch(
        id="t",
        description="",
        file="a.exe",
        signature="48 8B 05 ?? ?? ?? ??",
        replace="48 8B 05 11 22 33 44",
        expect="48 8B 05 DE AD BE EF",
    )
    out, res = patcher.apply_patch_to_bytes(data, patch)
    assert res.status == "applied"
    assert out != data, "the patch must actually have changed something"

    assert buildid.fingerprint(out) == buildid.fingerprint(data)


def test_fingerprint_survives_signature_stripping():
    """``strip_signature`` only truncates a trailing blob and zeroes a directory
    entry, so it must not disturb the identity either."""
    base = _pe_with_text(b"\x90" * 16, rdata=b"x\x00")
    # Append a fake WIN_CERTIFICATE and point the security directory at it.
    cert = b"\x08\x00\x00\x00\x00\x02\x02\x00" + b"\x00" * 8
    data = bytearray(base) + cert
    pe_off = struct.unpack_from("<I", bytes(data), 0x3C)[0]
    opt = pe_off + 24
    dirs = opt + 112
    entry = dirs + 4 * 8
    struct.pack_into("<II", data, entry, len(base), len(cert))
    data = bytes(data)

    assert pe.parse(data).has_signature
    stripped, changed = pe.strip_signature(data)
    assert changed
    assert not pe.parse(stripped).has_signature

    # strip_signature rewrites the checksum, which is outside the fingerprinted
    # regions, so the identity must be unchanged.
    assert buildid.fingerprint(stripped) == buildid.fingerprint(data)


def test_fingerprint_changes_when_rdata_changes():
    """A different string table means a different vendor build."""
    a = _pe_with_text(b"\x90" * 16, rdata=b"mainFaqMenuItem\x00")
    b = _pe_with_text(b"\x90" * 16, rdata=b"mainAboutMenuItem\x00")
    assert buildid.fingerprint(a) != buildid.fingerprint(b)


def test_fingerprint_changes_when_the_timestamp_changes():
    a = _pe_with_text(b"\x90" * 16)
    b = bytearray(a)
    struct.pack_into("<I", b, 0x88, 0x6ABBE81C)
    assert buildid.fingerprint(a) != buildid.fingerprint(bytes(b))


def test_fingerprint_changes_when_the_image_size_changes():
    a = _pe_with_text(b"\x90" * 16)
    b = bytearray(a)
    struct.pack_into("<I", b, 0x98 + 56, 0x1D49000)
    assert buildid.fingerprint(a) != buildid.fingerprint(bytes(b))


def test_fingerprint_ignores_text_bytes():
    """By design: ``.text`` is what we rewrite, so it cannot be part of identity.

    This is the deliberate trade-off, pinned so it is not "fixed" later by
    someone who expects a content hash.  A new vendor build that changed *only*
    code and not one byte of data, the timestamp or the image size would alias
    -- and would also be caught by the per-patch signature checks, which is the
    real gate.
    """
    a = _pe_with_text(b"\x90" * 16, rdata=b"same\x00")
    b = _pe_with_text(b"\xcc" * 16, rdata=b"same\x00")
    assert buildid.fingerprint(a) == buildid.fingerprint(b)


# --------------------------------------------------------------------------- #
# check()
# --------------------------------------------------------------------------- #
def test_check_returns_none_when_no_build_recorded():
    data = _pe_with_text(b"\x90" * 16)
    assert buildid.check(data, "a.exe", None) is None


def test_check_returns_none_on_a_match():
    data = _pe_with_text(b"\x90" * 16)
    fp = buildid.fingerprint(data)
    assert buildid.check(data, "a.exe", fp) is None


def test_check_reports_a_mismatch_with_both_fingerprints():
    data = _pe_with_text(b"\x90" * 16)
    mm = buildid.check(data, "a.exe", "deadbeefdeadbeef")
    assert mm is not None
    assert mm.expected == "deadbeefdeadbeef"
    assert mm.actual == buildid.fingerprint(data)
    assert "authored against build deadbeefdeadbeef" in mm.describe()
    assert "a.exe" in mm.describe()


def test_check_on_a_non_pe_raises():
    with pytest.raises(pe.PEError):
        buildid.check(b"not a PE", "a.exe", "deadbeefdeadbeef")
