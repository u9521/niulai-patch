"""Tests for the semantic locators.

The engine tests here are built on synthetic images rather than the real MuMu
binaries, because the suite has to run on a machine with no MuMu installed.
``test_locate_against_real_binaries.py``-style checks live in
``tests/test_robustness.py``, which skips when the backups are absent.

The behaviours worth pinning, in order of how much they cost to get wrong:

* the compound rule -- anchor *and* signature must agree -- is what makes a
  non-unique string usable, and it must refuse when the pair is not unique;
* every failure mode raises, so the engine fails closed;
* ``LocatorUnavailable`` is raised rather than falling back when capstone is
  missing.
"""

from __future__ import annotations

import struct

import pytest

from pe import locate, patcher, pe, sigscan

requires_capstone = pytest.mark.skipif(
    not locate.HAVE_CAPSTONE, reason="capstone (optional) is not installed"
)


# --------------------------------------------------------------------------- #
# synthetic PE with a .text and a .rdata
# --------------------------------------------------------------------------- #
def _pe(text: bytes, rdata: bytes, *, text_rva: int = 0x1000, rdata_rva: int = 0x20000) -> bytes:
    """A two-section PE32+ good enough for the locator to walk."""
    text_raw = max(0x200, (len(text) + 0x1FF) // 0x200 * 0x200)
    rdata_raw = max(0x200, (len(rdata) + 0x1FF) // 0x200 * 0x200)
    buf = bytearray(0x200 + text_raw + rdata_raw)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", buf, 0x84, 0x8664)
    struct.pack_into("<H", buf, 0x86, 2)
    struct.pack_into("<H", buf, 0x94, 0xF0)
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<Q", buf, opt + 24, 0x140000000)
    struct.pack_into("<I", buf, opt + 56, 0x30000)
    struct.pack_into("<I", buf, opt + 108, 16)
    sec = opt + 0xF0
    buf[sec : sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", buf, sec + 8, text_raw, text_rva, text_raw, 0x200)
    struct.pack_into("<I", buf, sec + 36, 0x60000020)
    buf[0x200 : 0x200 + len(text)] = text
    o = sec + 40
    buf[o : o + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", buf, o + 8, rdata_raw, rdata_rva, rdata_raw, 0x200 + text_raw)
    struct.pack_into("<I", buf, o + 36, 0x40000040)
    start = 0x200 + text_raw
    buf[start : start + len(rdata)] = rdata
    return bytes(buf)


def _lea_to(target_rva: int, insn_rva: int, reg: int = 2) -> bytes:
    """`lea rXX, [rip+disp32]` at ``insn_rva`` pointing at ``target_rva``."""
    disp = target_rva - (insn_rva + 7)
    return bytes([0x48, 0x8D, 0x05 | (reg << 3)]) + struct.pack("<i", disp)


def _nops(n: int) -> bytes:
    return b"\x90" * n


# --------------------------------------------------------------------------- #
# Locator parsing / validation
# --------------------------------------------------------------------------- #
def test_parse_locator_reads_kind_value_window():
    loc = locate.parse_locator(
        {"kind": "string-ref", "value": "mainFaqMenuItem", "window": "0x100"}
    )
    assert loc.kind == "string-ref"
    assert loc.value == "mainFaqMenuItem"
    assert loc.window == 0x100


def test_parse_locator_defaults_the_window():
    loc = locate.parse_locator({"kind": "string-ref", "value": "x"})
    assert loc.window == 0x100


def test_parse_locator_rejects_an_unknown_kind():
    with pytest.raises(locate.LocatorError, match="unknown locator kind"):
        locate.parse_locator({"kind": "vibes", "value": "x"})


def test_parse_locator_rejects_a_missing_key():
    with pytest.raises(locate.LocatorError, match="missing key"):
        locate.parse_locator({"kind": "string-ref"})


def test_parse_locator_rejects_a_non_table():
    with pytest.raises(locate.LocatorError, match="must be a table"):
        locate.parse_locator("mainFaqMenuItem")


def test_locator_rejects_a_non_positive_window():
    with pytest.raises(locate.LocatorError, match="window must be positive"):
        locate.Locator(kind="string-ref", value="x", window=0)


def test_locator_rejects_an_empty_value():
    with pytest.raises(locate.LocatorError, match="non-empty"):
        locate.Locator(kind="string-ref", value="")


# --------------------------------------------------------------------------- #
# LocatorError is a SignatureError, so every existing handler already treats a
# failed location as fatal without needing to know about locators.
# --------------------------------------------------------------------------- #
def test_locator_error_is_a_signature_error():
    assert issubclass(locate.LocatorError, sigscan.SignatureError)
    assert issubclass(locate.LocatorUnavailable, locate.LocatorError)


# --------------------------------------------------------------------------- #
# string-ref
# --------------------------------------------------------------------------- #
@requires_capstone
def test_string_ref_finds_the_site_after_the_anchor():
    rdata_rva = 0x20000
    text = _nops(16) + _lea_to(rdata_rva, 0x1000 + 16) + _nops(16)
    data = _pe(text, b"mainFaqMenuItem\0", rdata_rva=rdata_rva)
    loc = locate.Locator(kind="string-ref", value="mainFaqMenuItem", window=0x40)
    sig = sigscan.parse_signature("48 8D 15 ?? ?? ?? ??")
    res = locate.resolve(data, loc, sig)
    assert res.rva == 0x1000 + 16
    assert res.anchors == (0x1000 + 16,)


@requires_capstone
def test_string_ref_requires_an_exact_match_not_a_prefix():
    """The real reason: `[GameToolsPresenter::fetchGameToolsConfig]` is a prefix
    of longer log strings, and a prefix match would pull in unrelated anchors."""
    rdata_rva = 0x20000
    blob = b"fetchGameToolsConfig\0fetchGameToolsConfig: more\0"
    text = _nops(8) + _lea_to(rdata_rva + 20, 0x1000 + 8) + _nops(8)
    data = _pe(text, blob, rdata_rva=rdata_rva)
    # The shorter literal is present in .rdata but never referenced.
    loc = locate.Locator(kind="string-ref", value="fetchGameToolsConfig", window=0x40)
    sig = sigscan.parse_signature("48 8D 15 ?? ?? ?? ??")
    with pytest.raises(locate.LocatorError, match="no reference"):
        locate.resolve(data, loc, sig)


@requires_capstone
def test_string_ref_errors_when_the_string_is_absent():
    data = _pe(_nops(32), b"something else\0")
    loc = locate.Locator(kind="string-ref", value="mainFaqMenuItem", window=0x40)
    sig = sigscan.parse_signature("48 8D 15 ?? ?? ?? ??")
    with pytest.raises(locate.LocatorError, match="matched no reference"):
        locate.resolve(data, loc, sig)


@requires_capstone
def test_string_ref_errors_when_the_signature_is_not_near_the_anchor():
    rdata_rva = 0x20000
    text = _nops(16) + _lea_to(rdata_rva, 0x1000 + 16) + _nops(16)
    data = _pe(text, b"mainFaqMenuItem\0", rdata_rva=rdata_rva)
    loc = locate.Locator(kind="string-ref", value="mainFaqMenuItem", window=0x40)
    # A signature that is nowhere in the image.
    sig = sigscan.parse_signature("CC CC CC CC CC CC CC CC")
    with pytest.raises(locate.LocatorError, match="matched nothing within"):
        locate.resolve(data, loc, sig)


# --------------------------------------------------------------------------- #
# the compound rule
# --------------------------------------------------------------------------- #
@requires_capstone
def test_compound_rule_resolves_when_only_one_pair_matches():
    """The load-bearing behaviour.

    Two references to the same string, and a signature that occurs at both.  The
    window is chosen so that each reference sees only *its own* neighbouring
    site: the pair (ref1, site1) and (ref2, site2) both exist, so the result is
    ambiguous -- which is correct, because the two sites are genuinely
    indistinguishable by this locator and the patch must not guess.
    """
    rdata_rva = 0x20000
    text = bytearray(_nops(0x200))
    # Reference and its site, twice, far enough apart that neither window
    # reaches the other pair.
    text[0x10:0x17] = _lea_to(rdata_rva, 0x1000 + 0x10)
    text[0x20:0x28] = bytes.fromhex("488B05DEADBEEF")
    text[0x110:0x117] = _lea_to(rdata_rva, 0x1000 + 0x110)
    text[0x120:0x128] = bytes.fromhex("488B05DEADBEEF")
    data = _pe(bytes(text), b"avatarButton\0", rdata_rva=rdata_rva)

    sig = sigscan.parse_signature("48 8B 05 ?? ?? ?? ??")
    loc = locate.Locator(kind="string-ref", value="avatarButton", window=0x40)
    with pytest.raises(locate.LocatorError, match="candidate"):
        locate.resolve(data, loc, sig)


@requires_capstone
def test_compound_rule_is_unique_when_only_one_pair_matches():
    """One reference whose window contains a site, plus a second reference whose
    window contains none.  The conjunction is unique, so it resolves."""
    rdata_rva = 0x20000
    text = bytearray(_nops(0x200))
    text[0x10:0x17] = _lea_to(rdata_rva, 0x1000 + 0x10)
    text[0x20:0x28] = bytes.fromhex("488B05DEADBEEF")
    # A second reference with no matching signature anywhere near it.
    text[0x110:0x117] = _lea_to(rdata_rva, 0x1000 + 0x110)
    data = _pe(bytes(text), b"avatarButton\0", rdata_rva=rdata_rva)

    sig = sigscan.parse_signature("48 8B 05 ?? ?? ?? ??")
    loc = locate.Locator(kind="string-ref", value="avatarButton", window=0x40)
    res = locate.resolve(data, loc, sig)
    assert res.rva == 0x1020
    assert len(res.anchors) == 2, "both references are reported"


@requires_capstone
def test_multiple_candidates_are_refused_with_their_rvas():
    """Ambiguity must be fatal and must name the sites, never pick the first."""
    rdata_rva = 0x20000
    text = bytearray(_nops(0x200))
    text[0x10:0x17] = _lea_to(rdata_rva, 0x1000 + 0x10)
    text[0x20:0x28] = bytes.fromhex("488B05DEADBEEF")
    text[0x110:0x117] = _lea_to(rdata_rva, 0x1000 + 0x110)
    text[0x120:0x128] = bytes.fromhex("488B05DEADBEEF")
    data = _pe(bytes(text), b"duplicate\0", rdata_rva=rdata_rva)
    loc = locate.Locator(kind="string-ref", value="duplicate", window=0x40)
    sig = sigscan.parse_signature("48 8B 05 ?? ?? ?? ??")
    with pytest.raises(locate.LocatorError) as ei:
        locate.resolve(data, loc, sig)
    assert "candidate" in str(ei.value)
    assert "0x1020" in str(ei.value) and "0x1120" in str(ei.value)


# --------------------------------------------------------------------------- #
# RVA-contiguity of the window scan
# --------------------------------------------------------------------------- #
@requires_capstone
def test_window_scan_does_not_cross_a_section_boundary():
    """A window straddling two sections must not read them as adjacent bytes.

    Sections are laid out in RVA space, and the gap between ``.text`` and
    ``.rdata`` here is large (RVA 0x11FF -> 0x20000).  A raw byte slice ignores
    that gap: it would splice the last bytes of ``.text`` onto the first bytes of
    ``.rdata`` and "find" a signature that does not exist anywhere in memory.

    The pattern is placed exactly across that raw seam, so it is only findable by
    a naive slice.  ``.text`` is a full 0x200 raw bytes, so its last byte is RVA
    0x11FF and the next raw byte belongs to ``.rdata`` at RVA 0x20000.
    """
    rdata_rva = 0x20000
    text = bytearray(_nops(0x200))
    text[0x10:0x17] = _lea_to(rdata_rva + 4, 0x1000 + 0x10)
    # First half of the pattern at the very end of .text's raw data.
    text[0x1F8:] = bytes.fromhex("AA BB CC DD EE FF 11 22")
    # Second half at the very start of .rdata's raw data.
    rdata = bytes.fromhex("33 44 55 66") + b"anchor\0"
    data = _pe(bytes(text), rdata, rdata_rva=rdata_rva)

    info = pe.parse(data)
    # The two halves are in different sections, and there is no RVA between them.
    assert pe.rva_to_offset(info, 0x11F8) is not None
    assert pe.rva_to_offset(info, 0x1200) is None, "no RVA in the inter-section gap"
    assert pe.rva_to_offset(info, rdata_rva) is not None
    # The anchor really is referenced, so the test reaches the window scan.
    idx = locate.Index.for_data(data)
    assert idx.anchors_for(locate.Locator(kind="string-ref", value="anchor", window=0x40)) == [
        0x1010
    ]

    loc = locate.Locator(kind="string-ref", value="anchor", window=0x800)
    spliced = sigscan.parse_signature("AA BB CC DD EE FF 11 22 33 44 55 66")
    with pytest.raises(locate.LocatorError, match="matched nothing within"):
        locate.resolve(data, loc, spliced)


@requires_capstone
def test_window_scan_finds_a_site_before_the_anchor():
    """The window is symmetric: a site may sit before its anchor."""
    rdata_rva = 0x20000
    text = bytearray(_nops(0x40))
    text[0x10:0x17] = _lea_to(rdata_rva, 0x1000 + 0x10)
    text[0x20:0x28] = bytes.fromhex("488B05DEADBEEF")
    data = _pe(bytes(text), b"anchor\0", rdata_rva=rdata_rva)
    loc = locate.Locator(kind="string-ref", value="anchor", window=0x20)
    sig = sigscan.parse_signature("48 8B 05 ?? ?? ?? ??")
    res = locate.resolve(data, loc, sig)
    assert res.rva == 0x1020


# --------------------------------------------------------------------------- #
# capstone absence
# --------------------------------------------------------------------------- #
def test_missing_capstone_raises_rather_than_falling_back(monkeypatch):
    """Fail closed.  A silent fallback to a bare signature scan would resolve an
    ambiguous pattern to whichever site came first."""
    monkeypatch.setattr(locate, "HAVE_CAPSTONE", False)
    with pytest.raises(locate.LocatorUnavailable, match="capstone"):
        locate.require_capstone()


def test_a_patch_using_a_locator_fails_closed_without_capstone(monkeypatch):
    """The whole point of `LocatorUnavailable`: no silent fallback to a weaker
    strategy that could resolve to the wrong site."""
    monkeypatch.setattr(locate, "HAVE_CAPSTONE", False)
    # A fresh buffer, so no cached Index from an earlier test can be reused.
    data = _pe(
        _nops(16) + bytes.fromhex("488B05DEADBEEF") + _nops(16),
        b"noCapstone\0",
    )
    locate.Index._CACHE.clear()
    patch = patcher.Patch(
        id="t",
        description="",
        file="a.exe",
        signature="48 8B 05 ?? ?? ?? ??",
        replace="48 8B 05 11 22 33 44",
        expect="48 8B 05 DE AD BE EF",
        locate=locate.Locator(kind="string-ref", value="noCapstone", window=0x40),
    )
    with pytest.raises(locate.LocatorUnavailable):
        patcher.locate(data, patch)


def test_index_cache_does_not_alias_a_reused_buffer_address():
    """Regression: the first cache keyed on ``id(data)`` without holding a
    reference, so a freed buffer's address could be reused and served a stale
    index -- silently returning another file's sites."""
    a = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF") + _nops(16), b"first\0")
    key = (id(a), len(a))
    locate.Index._CACHE.clear()
    if locate.HAVE_CAPSTONE:
        idx_a = locate.Index.for_data(a)
        # Same id and length, but a different object at that address.
        b = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF") + _nops(16), b"second\0")
        locate.Index._CACHE[key] = (b, idx_a)  # simulate address reuse
        assert locate.Index.for_data(a) is not idx_a, (
            "a cache hit must be rejected when the stored buffer is not the one being asked about"
        )
    locate.Index._CACHE.clear()


# --------------------------------------------------------------------------- #
# import-call
# --------------------------------------------------------------------------- #
@requires_capstone
def test_import_call_matches_a_named_import(monkeypatch):
    """`import-call` resolves through the IAT, so the test stubs the slot map."""
    text = bytearray(_nops(0x20))
    text[0x10:0x16] = bytes.fromhex("FF15AABBCCDD")
    data = _pe(bytes(text), b"\0")
    idx = locate.Index.for_data(data)
    # Point the encoded slot at a name.
    slot = 0x1000 + 0x10 + 6 + struct.unpack("<i", bytes.fromhex("AABBCCDD"))[0]
    monkeypatch.setattr(idx, "_imports", {slot: "?addWidget@QBoxLayout@@"})
    idx.import_calls = [(0x1010, "?addWidget@QBoxLayout@@")]
    loc = locate.Locator(kind="import-call", value="?addWidget@QBoxLayout@@", window=0x40)
    sig = sigscan.parse_signature("FF 15 ?? ?? ?? ??")
    res = locate.resolve(data, loc, sig)
    assert res.rva == 0x1010


# --------------------------------------------------------------------------- #
# nearest_string, used by `rebase` diagnostics
# --------------------------------------------------------------------------- #
@requires_capstone
def test_nearest_string_finds_the_preceding_literal():
    rdata_rva = 0x20000
    text = _nops(8) + _lea_to(rdata_rva, 0x1000 + 8) + _nops(64)
    data = _pe(text, b"nearby\0", rdata_rva=rdata_rva)
    idx = locate.Index.for_data(data)
    assert idx.nearest_string(0x1000 + 8 + 40) == "nearby"


@requires_capstone
def test_nearest_string_returns_none_when_out_of_reach():
    rdata_rva = 0x20000
    text = _nops(8) + _lea_to(rdata_rva, 0x1000 + 8) + _nops(64)
    data = _pe(text, b"nearby\0", rdata_rva=rdata_rva)
    idx = locate.Index.for_data(data)
    assert idx.nearest_string(0x1000 + 8 + 40, reach=4) is None
