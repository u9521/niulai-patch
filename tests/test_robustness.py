"""Locator-robustness tests: the metric that justifies the semantic locators.

What is being measured
----------------------
``locate_rva`` and byte ``anchor`` both encode one particular link's layout.  A
vendor rebuild moves code, and every patch pinned that way stops resolving.  The
question these tests answer is: *how many patches survive a rebuild?*

How a rebuild is modelled
-------------------------
There is only one MuMu build on hand (6.8.2.0), so drift is simulated.  The
mutation is the honest one for this purpose: shift every section's RVA and raw
offset by N, and move the data directories with them.

That models "the vendor added N bytes of code before everything", and it is
deliberately kind to the *existing* locators in one respect -- rip-relative
references still resolve, because the source and its target move together.  So a
patch that survives this mutation survives the easy half of a real rebuild.  It
is not a substitute for rebasing against a real new release; it is a floor.

Why the mutation is not a runnable PE
-------------------------------------
The shift is applied to the section table and the headers, not to the
instruction encodings, so the result would not execute correctly (a rip-relative
reference whose displacement should have changed has not).  These tests only ever
*locate* sites in the mutant, never run it, and that is the property under test.

``shift_sections`` refuses to produce an image it cannot keep coherent: if the
first section does not start at the file's first raw byte, or the header is too
small to hold the tables, it raises rather than emitting a mutant whose failure
would be misread as a locator problem.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pe import locate, patcher, pe

# The pristine and patched binaries live in .backups/, which is gitignored.  A
# checkout without them must still run the rest of the suite.
MAIN = Path(".backups/6.8.2.0/20261006-161809/MuMuNxMain.exe")
DEVICE = Path(".backups/6.8.2.0/20261008-235500-7patch/MuMuNxDevice.exe")

needs_binaries = pytest.mark.skipif(
    not (MAIN.is_file() and DEVICE.is_file()),
    reason="pristine MuMu binaries are not present in .backups/",
)
needs_capstone = pytest.mark.skipif(
    not locate.HAVE_CAPSTONE, reason="capstone (optional) is not installed"
)


# --------------------------------------------------------------------------- #
# the mutation
# --------------------------------------------------------------------------- #
def shift_sections(data: bytes, delta: int) -> bytes:
    """Move every section and data directory by ``delta`` bytes.

    This is the model of "the vendor inserted code before everything else": all
    RVAs move together, so relative references between sections stay consistent.
    """
    if delta == 0:
        return data
    info = pe.parse(data)
    live = [s for s in info.sections if s.raw_size]
    if not live:
        raise ValueError("no sections with raw data to shift")

    first_raw = min(s.raw_offset for s in live)
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe_off + 24
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    num_dirs = struct.unpack_from("<I", data, opt + 108)[0]
    dirs_off = opt + 112
    sec_off = opt + opt_size

    # Grow the header region by `delta` so the inserted gap is real, then push
    # the rest of the file down by the same amount.
    buf = bytearray(data[:first_raw]) + bytearray(delta) + bytearray(data[first_raw:])

    # Section table: VirtualAddress and PointerToRawData both move.
    for i, s in enumerate(info.sections):
        o = sec_off + i * 40
        struct.pack_into("<II", buf, o + 8, s.virtual_size, s.virtual_address + delta)
        struct.pack_into("<II", buf, o + 20, s.raw_offset + delta, s.raw_size)

    # Every directory that points into the image moves.  The security directory
    # (index 4) is a file offset rather than an RVA, and is left alone.
    for index in range(min(num_dirs, 16)):
        entry = dirs_off + index * 8
        va = struct.unpack_from("<I", buf, entry)[0]
        if index == pe.IMAGE_DIRECTORY_ENTRY_SECURITY or va == 0:
            continue
        struct.pack_into("<I", buf, entry, va + delta)

    struct.pack_into("<I", buf, opt + 56, info.size_of_image + delta)

    # The import tables have to move *with* the sections, not just be pointed at
    # by a shifted directory entry.
    #
    # This was a real gap, invisible until the first `import-call` locator
    # existed: the 20 `string-ref` locators only need `.text` decoded, so a
    # mutant whose `.idata` still named pre-shift RVAs resolved fine for them.
    # But `_import_slots` maps IAT slots through pefile, and pefile walks the
    # IMAGE_IMPORT_DESCRIPTOR chain *by RVA* -- so leaving those stale made it
    # parse 513 of 4318 imports and every import-call locator fail.  That would
    # have been misread as "the locator is not shift-robust" when in fact the
    # mutant was not coherent.
    _shift_import_rvas(buf, info, delta)
    return bytes(buf)


def _shift_import_rvas(buf: bytearray, info: pe.PEInfo, delta: int) -> None:
    """Add ``delta`` to every RVA inside the import directory.

    An IMAGE_IMPORT_DESCRIPTOR holds three RVAs -- ``OriginalFirstThunk`` (the
    import lookup table), ``Name`` (the DLL name) and ``FirstThunk`` (the IAT) --
    plus two non-RVA fields, ``TimeDateStamp`` and ``ForwarderChain``, which must
    be left alone.  Each thunk array in turn holds one 64-bit entry per import:
    either an RVA to an IMAGE_IMPORT_BY_NAME (bit 63 clear) or an ordinal (bit 63
    set).  Only the former is an address and only the former moves.

    ``info`` describes the *unshifted* image and ``buf`` is the shifted one.  The
    directory entry is read back out of ``buf``, so it is already advanced; it
    has to be brought back into ``info``'s coordinate space before the section
    table can map it, and the resulting offset advanced again to index ``buf``.
    """
    shifted = _data_directory_rva(buf, pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
    if not shifted:
        return
    desc_off = pe.rva_to_offset(info, shifted - delta)
    if desc_off is None:
        return
    desc_off += delta

    # Descriptors are contiguous 20-byte records, terminated by an all-zero one.
    # Bound the walk so a malformed table cannot spin.
    for _ in range(0x1000):
        if desc_off + 20 > len(buf):
            return
        original_first_thunk, _stamp, _chain, name, first_thunk = struct.unpack_from(
            "<IIIII", buf, desc_off
        )
        if not (original_first_thunk or name or first_thunk):
            return
        for index, value in ((0, original_first_thunk), (12, name), (16, first_thunk)):
            if value:
                struct.pack_into("<I", buf, desc_off + index, value + delta)
        for thunk_rva in (original_first_thunk, first_thunk):
            if thunk_rva:
                _shift_thunk_array(buf, info, thunk_rva, delta)
        desc_off += 20


def _shift_thunk_array(buf: bytearray, info: pe.PEInfo, thunk_rva: int, delta: int) -> None:
    """Rewrite the name RVAs in one IMAGE_THUNK_DATA array."""
    off = pe.rva_to_offset(info, thunk_rva)
    if off is None:
        return
    off += delta
    for _ in range(0x10000):
        if off + 8 > len(buf):
            return
        (value,) = struct.unpack_from("<Q", buf, off)
        if value == 0:
            return
        if not (value >> 63):  # import by name, not by ordinal
            struct.pack_into("<I", buf, off, (value & 0xFFFFFFFF) + delta)
        off += 8


def _data_directory_rva(buf: bytearray, index: int) -> int | None:
    """Read data directory ``index`` out of the (possibly rewritten) buffer."""
    pe_off = struct.unpack_from("<I", buf, 0x3C)[0]
    opt = pe_off + 24
    num_dirs = struct.unpack_from("<I", buf, opt + 108)[0]
    if index >= num_dirs:
        return None
    return struct.unpack_from("<I", buf, opt + 112 + index * 8)[0] or None


# --------------------------------------------------------------------------- #
# the mutation must actually model what it claims
# --------------------------------------------------------------------------- #
@needs_binaries
def test_shift_moves_every_rva():
    data = MAIN.read_bytes()
    before = pe.parse(data)
    after = pe.parse(shift_sections(data, 0x1000))
    assert after.num_sections == before.num_sections
    for b, a in zip(before.sections, after.sections, strict=True):
        assert a.virtual_address == b.virtual_address + 0x1000
        assert a.raw_offset == b.raw_offset + 0x1000
        assert a.name == b.name


@needs_binaries
def test_shift_preserves_section_contents():
    """Every section survives the shift byte-for-byte, except the import tables.

    The shift is a *relocation*: code and data move but are not otherwise edited,
    which is what makes it a fair test of the locators.  The one deliberate
    exception is ``.idata``: an IMAGE_IMPORT_DESCRIPTOR and its thunk arrays are
    made of RVAs, so a shift that moved the sections without moving those would
    leave a mutant whose import directory points at pre-shift addresses.  That is
    not a relocation, it is a corrupt image -- see ``_shift_import_rvas``.
    """
    data = MAIN.read_bytes()
    mutant = shift_sections(data, 0x40)
    before = pe.parse(data)
    after = pe.parse(mutant)
    for b, a in zip(before.sections, after.sections, strict=True):
        name = b.name.strip("\x00")
        if name == ".idata":
            assert (
                mutant[a.raw_offset : a.raw_offset + a.raw_size]
                != data[b.raw_offset : b.raw_offset + b.raw_size]
            ), ".idata must have been relocated, not copied verbatim"
            continue
        assert (
            mutant[a.raw_offset : a.raw_offset + a.raw_size]
            == data[b.raw_offset : b.raw_offset + b.raw_size]
        ), f"{name} must survive the shift unchanged"


@needs_binaries
def test_shift_keeps_the_import_table_coherent():
    """The mutant's import directory must still parse, at the shifted RVAs.

    This is the property whose absence hid a gap for as long as every locator was
    a ``string-ref``.  A ``string-ref`` only needs ``.text`` decoded, so a mutant
    with a stale import directory resolved fine for all 20 of them; the first
    ``import-call`` locator then failed, and the failure looked like "this
    locator is not shift-robust" rather than "this mutant is not coherent".

    Asserted by symbol count, not by re-deriving the same arithmetic the mutation
    uses: pefile walks the descriptor chain by RVA, so an equal count is evidence
    that the chain is intact end to end.
    """
    pefile = pytest.importorskip("pefile")

    for path in (MAIN, DEVICE):
        data = path.read_bytes()

        def symbols(blob: bytes) -> int:
            pf = pefile.PE(data=blob, fast_load=True)
            try:
                pf.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                )
                entries = getattr(pf, "DIRECTORY_ENTRY_IMPORT", []) or []
                return sum(len(e.imports) for e in entries)
            finally:
                pf.close()

        baseline = symbols(data)
        assert baseline > 0, f"{path.name}: baseline has no imports to compare"
        for delta in (0x40, 0x1000):
            got = symbols(shift_sections(data, delta))
            assert got == baseline, (
                f"{path.name}: after a {delta:#x}-byte shift the import table "
                f"parsed {got} symbols, not {baseline}; the mutant is corrupt"
            )


@needs_binaries
def test_shift_keeps_rva_to_offset_consistent():
    """An RVA that resolved before must still resolve, to shifted bytes."""
    data = MAIN.read_bytes()
    delta = 0x1000
    mutant = shift_sections(data, delta)
    before, after = pe.parse(data), pe.parse(mutant)
    for b, _a in zip(before.sections, after.sections, strict=True):
        if not b.raw_size:
            continue
        for probe in (b.virtual_address, b.virtual_address + 0x40):
            o1 = pe.rva_to_offset(before, probe)
            o2 = pe.rva_to_offset(after, probe + delta)
            assert o1 is not None and o2 is not None
            assert o2 == o1 + delta


@needs_binaries
def test_shift_is_the_identity_at_zero():
    data = MAIN.read_bytes()
    assert shift_sections(data, 0) == data


@needs_binaries
def test_shift_rejects_an_image_that_cannot_be_parsed():
    """A mutant must never be produced from something we do not understand.

    Truncating the file to the headers leaves no section table to shift; the
    right answer is to refuse loudly, because a silently-wrong mutant would make
    a locator failure look like a robustness failure.
    """
    with pytest.raises(pe.PEError):
        shift_sections(MAIN.read_bytes()[:0x200], 0x40)


# --------------------------------------------------------------------------- #
# caching: one Index build per distinct image, not one per test
# --------------------------------------------------------------------------- #
# Building the semantic index means a full capstone sweep of .text: measured at
# ~4.5 s for MuMuNxMain.exe and ~6 s for MuMuNxDevice.exe.  `locate.Index` caches
# by *object identity* of the bytes it was given, so a test that calls
# `path.read_bytes()` gets a fresh object and pays for a fresh sweep -- and five
# of the tests below each did exactly that, several of them on the same image.
#
# These helpers hand every caller the same object for the same image, so the
# index is built once per image rather than once per test.
SHIFT_DELTA = 0x1000

_pristine_cache: dict[str, bytes] = {}
_mutant_cache: dict[tuple[str, int], bytes] = {}


def pristine(path: Path) -> bytes:
    """The vendor bytes for ``path``, read once per session."""
    key = str(path)
    if key not in _pristine_cache:
        _pristine_cache[key] = path.read_bytes()
    return _pristine_cache[key]


def mutant(path: Path, delta: int = SHIFT_DELTA) -> bytes:
    """The shifted image for ``path``, built once per session."""
    key = (str(path), delta)
    if key not in _mutant_cache:
        _mutant_cache[key] = shift_sections(pristine(path), delta)
    return _mutant_cache[key]


# --------------------------------------------------------------------------- #
# the baseline, then the target
# --------------------------------------------------------------------------- #
#: The one patch that is deliberately not shift-robust.  ``locate_rva`` is an
#: absolute address, so a section shift invalidates it *by definition* -- this is
#: a property of the choice, not a defect to be fixed by tuning.  It is kept
#: because the self-integrity check's predicate resolves ``WinVerifyTrust``
#: through a dynamically loaded pointer, so there is no import name to anchor on
#: and no string literal within reach (verified: CRYPT32 is imported only for
#: ``CertGetNameStringW``/``CryptQueryObject``/... and ``WinVerifyTrust`` appears
#: in no import table at all).  ``rebase`` reports it as needing manual work.
KNOWN_NOT_SHIFT_ROBUST = {"integrity-check-clean-exit"}


def _patch_target(data: bytes, patch: patcher.Patch) -> int:
    """The RVA this patch is expected to land on."""
    if patch.locate_rva is not None:
        return patch.locate_rva
    return patch.known_rvas[0]


def _profiles_for(file: str) -> list[patcher.Profile]:
    return [
        prof
        for prof in patcher.load_profiles().values()
        if any(p.file == file for p in prof.patches)
    ]


def _shift_robust_patches(file: str) -> list[patcher.Patch]:
    """Every patch on ``file`` that must survive a rebuild.

    Excludes the one documented ``locate_rva`` exception, which is measured
    separately by ``test_the_documented_exception_still_fails_closed``.
    """
    return [
        p
        for prof in _profiles_for(file)
        for p in prof.patches
        if p.file == file and p.id not in KNOWN_NOT_SHIFT_ROBUST
    ]


@needs_binaries
@needs_capstone
def test_every_patch_survives_a_section_shift():
    """The headline property: every non-exempt patch tracks a rebuild exactly.

    Before the semantic locators this was 3/13 on the Main binary: a shift broke
    every ``locate_rva`` patch.  The target is every patch that is not
    deliberately build-specific, on both binaries.

    This asserts *exact tracking* -- the site must move by precisely the shift,
    no more and no less -- rather than merely "a site was found".  That is
    strictly stronger and subsumes the weaker check: a patch that resolves to the
    wrong place passes "it resolved" but fails here, and an off-by-N anchor bug is
    exactly the failure mode this suite exists to catch.

    Only one shift is exercised.  A semantic locator never consults an absolute
    address, so if it tracks one shift it tracks any; a second delta re-ran the
    same multi-second index build per binary to re-test a property that cannot
    vary with it.  ``test_shift_moves_every_rva`` still pins the mutation itself.
    """
    delta = SHIFT_DELTA
    failures: list[str] = []
    checked = 0
    for path, file in (
        (MAIN, "nx_main/MuMuNxMain.exe"),
        (DEVICE, "nx_device/15.0/shell/MuMuNxDevice.exe"),
    ):
        data = mutant(path, delta)
        for patch in _shift_robust_patches(file):
            checked += 1
            assert patch.locate is not None, (
                f"{patch.id} is not in KNOWN_NOT_SHIFT_ROBUST but has no "
                f"semantic locator; it cannot be expected to survive a rebuild"
            )
            want = _patch_target(data, patch) + delta
            try:
                got = patcher.locate(data, patch).rva
            except Exception as exc:
                failures.append(f"{patch.id}: {type(exc).__name__}")
                continue
            if got != want:
                failures.append(f"{patch.id}: got {got:#x}, want {want:#x}")
    assert checked > 0, "no patches were checked; the profile set looks wrong"
    assert not failures, f"{failures} after a {delta:#x}-byte shift"


@needs_binaries
@needs_capstone
def test_the_documented_exception_still_fails_closed():
    """The exception must fail *safely*, not silently mis-patch.

    This is the property that makes keeping one ``locate_rva`` acceptable: after
    a shift it refuses, and the refusal names the build mismatch.  A version of
    this patch that resolved to the wrong place would be far worse than one that
    does not resolve at all.
    """
    data = mutant(MAIN)
    patch = next(
        p
        for prof in patcher.load_profiles().values()
        for p in prof.patches
        if p.id == "integrity-check-clean-exit"
    )
    with pytest.raises(Exception) as ei:
        patcher.locate(data, patch)
    assert "different build" in str(ei.value)


@needs_binaries
@needs_capstone
def test_no_shipped_patch_still_depends_on_a_build_specific_locator():
    """Except the one that is documented as having no alternative.

    ``locate_rva`` and byte ``anchor`` both pin a build layout.  A new one
    creeping back in silently is the regression this catches.
    """
    offenders = [
        f"{prof.name}/{p.id}"
        for prof in patcher.load_profiles().values()
        for p in prof.patches
        if p.is_build_specific() and p.id not in KNOWN_NOT_SHIFT_ROBUST
    ]
    assert not offenders, (
        "these patches locate their site from a build-specific number; give "
        f"them a `locate` locator instead: {offenders}"
    )


@needs_binaries
@needs_capstone
def test_the_documented_exception_is_still_the_only_one():
    """Pin the count, so removing the exception is a deliberate act."""
    build_specific = {
        p.id
        for prof in patcher.load_profiles().values()
        for p in prof.patches
        if p.is_build_specific()
    }
    assert build_specific == KNOWN_NOT_SHIFT_ROBUST, (
        f"the set of build-specific patches changed: {sorted(build_specific)}"
    )


# --------------------------------------------------------------------------- #
# the locators resolve to the recorded sites on the *unmutated* binary
# --------------------------------------------------------------------------- #
@needs_binaries
@needs_capstone
def test_every_semantic_locator_lands_on_its_recorded_rva():
    """A locator must reproduce the RVA the profile was authored against.

    This is the check that a locator is *correct*, not merely stable: it would
    catch an anchor that resolves consistently to the wrong neighbouring site.
    """
    for path, file in (
        (MAIN, "nx_main/MuMuNxMain.exe"),
        (DEVICE, "nx_device/15.0/shell/MuMuNxDevice.exe"),
    ):
        data = pristine(path)
        for prof in _profiles_for(file):
            for patch in prof.patches:
                if patch.file != file or patch.locate is None:
                    continue
                match = patcher.locate(data, patch)
                expected = _patch_target(data, patch)
                assert match.rva == expected, (
                    f"{patch.id}: locator found {match.rva:#x}, profile records {expected:#x}"
                )


@needs_binaries
@needs_capstone
def test_an_ambiguous_locator_is_refused_rather_than_guessed():
    """Widening a window until it sees a second site must be fatal.

    This is what stops the robustness property from being bought with
    recklessness: a locator that resolves is only meaningful if resolving to
    more than one site is an error.
    """
    data = pristine(MAIN)
    patch = next(
        p for prof in patcher.load_profiles().values() for p in prof.patches if p.id == "menu-faq"
    )
    assert patch.locate is not None
    from pe import locate as locate_mod

    greedy = locate_mod.Locator(kind=patch.locate.kind, value=patch.locate.value, window=0x20000)
    with pytest.raises(locate_mod.LocatorError, match="candidate"):
        locate_mod.resolve(data, greedy, patch.parsed_signature())
