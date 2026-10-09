"""Tests for the shipped patch profiles themselves.

These tests need no MuMu installation and no binaries: they assert that the
TOML profiles under ``src/pe/patches/`` are internally coherent and match
the intent their comments claim.  That matters because the profiles are data --
a typo in a hex string or a drifted ``locate_rva`` fails at *patch* time, on a
real install, with the emulator as the blast radius.

The highest-value checks here are the ones that catch a patch which would apply
but be wrong:

* a signature that pins bytes the replacement overwrites (the patch applies
  once, then ``verify`` reports it lost and a second run cannot find it);
* a ``locate_rva`` that disagrees with its ``known_rvas`` entry, i.e. the
  comment and the data have drifted apart;
* a "remove this menu item" patch that does not actually NOP a 5-byte call.
"""

from __future__ import annotations

from itertools import pairwise
from pathlib import Path

import pytest

from pe import patcher

PATCH_DIR = Path(patcher.PATCH_DIR)

# Every profile the package ships.  Listing them explicitly means a new file
# that fails to load is a test failure rather than a silent omission.
EXPECTED_PROFILES = {
    "device-ui",
    "no-device-integrity-punish",
    "no-device-telemetry",
    "no-integrity-punish",
    "no-telemetry",
    "remove-components",
}


def _load() -> dict[str, patcher.Profile]:
    return patcher.load_profiles()


def _all_patches() -> list[tuple[str, patcher.Patch]]:
    out = []
    for name, prof in _load().items():
        out.extend((name, p) for p in prof.patches)
    return out


def test_patch_dir_exists():
    assert PATCH_DIR.is_dir(), f"missing patch directory: {PATCH_DIR}"


def test_expected_profiles_are_present():
    assert set(_load()) == EXPECTED_PROFILES


def test_profiles_load_without_error():
    """``load_profiles`` runs ``Patch.validate`` on every patch.

    This is the test that catches "signature pins a byte the replacement
    overwrites", since validation raises ``PatchError`` at load time.
    """
    profiles = _load()
    assert profiles, "no profiles loaded"
    for name, prof in profiles.items():
        assert prof.patches, f"{name} declares no patches"


def test_profile_names_match_their_filenames():
    """The loader keys by the TOML's own [profile] name, falling back to the
    stem.  They should agree so `-p <name>` is predictable."""
    profiles = _load()
    for path in sorted(PATCH_DIR.glob("*.toml")):
        assert path.stem in profiles, (
            f"{path.name} declares a profile named something other than {path.stem!r}"
        )


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_signature_and_replacement_are_same_length(profile, patch):
    assert patch.parsed_signature().length == len(patch.replacement_bytes())


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_no_patch_overwrites_a_pinned_signature_byte(profile, patch):
    """The engine's own rule, restated as an explicit assertion.

    Redundant with ``validate`` on purpose: if ``validate`` is ever weakened,
    this still fails, and the failure names the offending offset.
    """
    sig = patch.parsed_signature()
    repl = patch.replacement_bytes()
    # Same length by construction -- asserted by
    # test_signature_and_replacement_are_same_length -- so a mismatch here
    # should be loud rather than silently truncated.
    for i, (token, new) in enumerate(zip(sig.tokens, repl, strict=True)):
        if token is not None:
            assert token == new, (
                f"{profile}/{patch.id}: signature pins byte {i} "
                f"({token:#04x}) but the replacement writes {new:#04x}; "
                f"the patch would be undetectable after applying"
            )


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_expect_matches_signature_with_wildcards_filled(profile, patch):
    """``expect`` must be a full literal consistent with the signature.

    If it is not, a wildcarded signature plus a stale ``expect`` would still be
    self-consistent to the engine (it compares against the file, not against
    the signature), so this cross-check is the only thing tying the two
    together.
    """
    if patch.expect is None:
        return
    sig = patch.parsed_signature()
    want = patcher.parse_hex_bytes(patch.expect)
    assert len(want) == sig.length
    for i, token in enumerate(sig.tokens):
        if token is not None:
            assert token == want[i], (
                f"{profile}/{patch.id}: expect[{i}] is {want[i]:#04x} but the "
                f"signature pins {token:#04x}"
            )


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_locate_rva_agrees_with_known_rvas(profile, patch):
    """A patch that pins an RVA must record that same RVA.

    ``known_rvas`` is documentation, and documentation drifts.  Tying it to
    ``locate_rva`` makes the drift a test failure.

    Patches that use a semantic locator instead are covered by
    ``test_semantic_locator_patches_record_the_rva_they_land_on`` below, which
    resolves the locator rather than comparing two literals.
    """
    if patch.locate_rva is None:
        return
    assert patch.known_rvas, f"{profile}/{patch.id}: locate_rva with no known_rvas"
    assert patch.known_rvas == [patch.locate_rva], (
        f"{profile}/{patch.id}: locate_rva {patch.locate_rva:#x} but known_rvas "
        f"{[hex(r) for r in patch.known_rvas]}"
    )


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_every_patch_records_the_rva_it_targets(profile, patch):
    """``known_rvas`` is what ties a profile to the build it was authored on.

    Every patch needs one -- including semantic-locator patches, whose locator
    finds the site but whose recorded RVA is what says *which* site was
    intended.  ``tests/test_robustness.py`` uses it to assert the locator lands
    where the profile claims.
    """
    assert patch.known_rvas, (
        f"{profile}/{patch.id}: no known_rvas; without one there is nothing to "
        f"check the locator against"
    )


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_patch_declares_exactly_one_resolver(profile, patch):
    """Two resolvers on one patch would silently shadow each other.

    ``_locate`` checks ``locate`` then ``locate_rva`` then ``anchor``, so a
    patch carrying more than one would quietly use the first and ignore the
    rest -- and the ignored field would look authoritative in the file.
    """
    declared = [
        name
        for name, present in (
            ("locate", patch.locate is not None),
            ("locate_rva", patch.locate_rva is not None),
            ("anchor", bool(patch.anchor)),
        )
        if present
    ]
    assert len(declared) <= 1, f"{profile}/{patch.id}: declares {declared}; keep exactly one"


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_anchored_patch_has_a_usable_signature(profile, patch):
    """A patch located by address still needs a signature to verify that address."""
    if patch.locate_rva is None and patch.anchor is None:
        return
    assert patch.signature.strip(), f"{profile}/{patch.id}: no signature"
    # A signature of all wildcards would verify nothing at the anchored RVA.
    assert any(t is not None for t in patch.parsed_signature().tokens), (
        f"{profile}/{patch.id}: signature is entirely wildcards, so it cannot "
        f"confirm the build at {patch.target_rva}"
    )


@pytest.mark.parametrize("profile, patch", _all_patches(), ids=lambda v: getattr(v, "id", v))
def test_patch_ids_are_unique_within_a_profile(profile, patch):
    prof = _load()[profile]
    ids = [p.id for p in prof.patches]
    assert len(ids) == len(set(ids)), f"{profile}: duplicate ids in {ids}"


def test_patch_ids_are_unique_across_profiles():
    """Two profiles writing the same id would confuse ``-p``/``--only``."""
    ids = [p.id for _, p in _all_patches()]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"patch id(s) used in more than one profile: {sorted(dupes)}"


def test_every_patch_targets_a_relative_path():
    """Patches must be relative to the install root, not absolute.

    ``install.resolve`` joins the profile's ``file`` onto the installation
    directory; an absolute or ``..`` path would escape it.
    """
    for _profile, patch in _all_patches():
        assert not patch.file.startswith(("/", "\\")), patch.file
        assert ":" not in patch.file, patch.file
        assert ".." not in Path(patch.file).parts, patch.file


# --------------------------------------------------------------------------- #
# Intent checks: the remove-components profile's menu patches
# --------------------------------------------------------------------------- #
MENU_PATCH_IDS = {
    "menu-message-center",
    "menu-redemption-center",
    "menu-faq",
    "menu-download-app",
}


def _menu_patches() -> list[patcher.Patch]:
    prof = _load()["remove-components"]
    return [p for p in prof.patches if p.id in MENU_PATCH_IDS]


def test_all_four_menu_patches_exist():
    assert {p.id for p in _menu_patches()} == MENU_PATCH_IDS


def test_kept_menu_items_are_not_patched():
    """关于 MuMu and 设置中心 are kept, so no patch may target their sites.

    Each menu item is created by a `call <factory>` at the end of its block.
    The two kept items' create calls are:

        设置中心  call at 0x168a6f, anchor 0x168a68
        关于 MuMu call at 0x169313, anchor 0x16930c

    Neither may appear as a patch site.  The 0xbd43 container-fill sites are
    likewise not patched at all.
    """
    forbidden = {0x168A68, 0x168A6F, 0x16930C, 0x169313}
    for _, p in _all_patches():
        if p.target_rva is not None:
            assert p.target_rva not in forbidden, (
                f"{p.id} patches a site reserved for a kept item ({p.target_rva:#x})"
            )


def test_container_fill_sites_are_not_patched():
    """The 0xbd43 sites must stay unpatched.

    They have no visible effect: 0xbd43 resolves to a container range-fill
    loop, not a menu operation.  Patching them is a silent no-op, so this test
    keeps them out of every profile.
    """
    stale = {0x1686B9, 0x1689B0, 0x168F78, 0x169258}
    for _, p in _all_patches():
        if p.target_rva is not None:
            assert p.target_rva not in stale, (
                f"{p.id} patches the container-fill site {p.target_rva:#x}, "
                f"which is known to have no effect on the menu"
            )


@pytest.mark.parametrize("patch", _menu_patches(), ids=lambda p: p.id)
def test_menu_patch_nops_a_five_byte_call(patch):
    """Each menu patch must replace a `call rel32` with five NOPs.

    This is the whole mechanism: the call to the item factory never happens, so
    the item is never constructed or added.  If a future edit changes the
    replacement to something else -- or shifts the anchor so the NOPs land on
    the wrong instruction -- this fails without needing the real binary.

    Note the sites legitimately contain other ``90`` bytes just after the call,
    so this identifies the NOP run by locating the ``E8`` in ``expect`` rather
    than by counting NOPs.
    """
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()

    # Exactly one E8 in the window, and it is the call being replaced.
    call_offsets = [i for i, b in enumerate(want) if b == 0xE8]
    assert len(call_offsets) == 1, (
        f"{patch.id}: expected exactly one 0xE8 in expect, found at "
        f"{[hex(i) for i in call_offsets]}"
    )
    idx = call_offsets[0]

    # The call is replaced by five contiguous NOPs...
    assert repl[idx : idx + 5] == b"\x90" * 5, (
        f"{patch.id}: bytes {idx}..{idx + 4} of the replacement are "
        f"{repl[idx : idx + 5].hex(' ')}, not five NOPs"
    )
    # ...and nothing else in the window changed.
    assert repl[:idx] == want[:idx], f"{patch.id}: bytes before the call changed"
    assert repl[idx + 5 :] == want[idx + 5 :], f"{patch.id}: bytes after the call changed"


@pytest.mark.parametrize("patch", _menu_patches(), ids=lambda p: p.id)
def test_menu_patch_call_displacements_are_distinct(patch):
    """The four menu sites are byte-identical apart from the call displacement.

    That is why a signature alone cannot find them and a `string-ref` locator
    is used instead, and it also means the displacement is the only thing that
    could ever disambiguate them by signature.  Asserting they differ documents
    the constraint: if two ever
    became equal, the profile comment claiming "byte-identical apart from the
    displacement" would be wrong.
    """
    others = [p for p in _menu_patches() if p.id != patch.id]
    mine = patcher.parse_hex_bytes(patch.expect)
    for other in others:
        theirs = patcher.parse_hex_bytes(other.expect)
        # They share a long common prefix but must differ somewhere.
        assert mine != theirs, f"{patch.id} and {other.id} have identical expect bytes"


def test_menu_patch_rvas_are_ascending_and_in_one_function():
    """All four create-call sites sit inside the menu builder 0x16803e-0x16939c."""
    rvas = sorted(p.known_rvas[0] for p in _menu_patches())
    assert rvas == [0x168424, 0x168771, 0x168D5F, 0x16902E]
    for r in rvas:
        assert 0x16803E <= r <= 0x16939C, f"{r:#x} is outside the menu function"


def test_menu_patches_agree_on_the_create_call_shape():
    """Every menu patch must NOP a call preceded by `mov rcx, rdi`.

    The item factories take the parent menu in rcx, so each create call is
    immediately preceded by `mov rcx, rdi` (48 8B CF).  That is what makes
    these sites the creation points rather than something else in the block;
    asserting it keeps a future edit from anchoring on a lookalike.
    """
    for p in _menu_patches():
        want = patcher.parse_hex_bytes(p.expect)
        # signature starts at `lea rdx,[rbp+..]` (4 bytes) then `mov rcx,rdi`
        assert want[4:7] == bytes.fromhex("488BCF"), (
            f"{p.id}: expected 48 8B CF (mov rcx,rdi) at offset 4, got {want[4:7].hex(' ')}"
        )
        # and the call immediately follows at offset 7
        assert want[7] == 0xE8, (
            f"{p.id}: expected the call opcode E8 at offset 7, got {want[7]:#04x}"
        )


# --------------------------------------------------------------------------- #
# Left navigation rail and system tray
# --------------------------------------------------------------------------- #
NAV_PATCH_IDS = {"nav-remote", "nav-cloudphone", "nav-feedback"}


def _patches(ids):
    prof = _load()["remove-components"]
    return [p for p in prof.patches if p.id in ids]


def test_all_three_nav_patches_exist():
    assert {p.id for p in _patches(NAV_PATCH_IDS)} == NAV_PATCH_IDS


@pytest.mark.parametrize("patch", _patches(NAV_PATCH_IDS), ids=lambda p: p.id)
def test_nav_patch_nops_an_indirect_call(patch):
    """Each nav patch must replace a 6-byte `call [rip+disp]` with six NOPs.

    The rail buttons are removed by skipping their QBoxLayout::addWidget, so
    the overwritten bytes must be an `FF 15 disp32` indirect call.
    """
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    offsets = [i for i in range(len(want) - 1) if want[i : i + 2] == b"\xff\x15"]
    assert len(offsets) == 1, (
        f"{patch.id}: expected exactly one FF 15 in expect, found {[hex(i) for i in offsets]}"
    )
    idx = offsets[0]
    assert repl[idx : idx + 6] == b"\x90" * 6, (
        f"{patch.id}: bytes {idx}..{idx + 5} of the replacement are "
        f"{repl[idx : idx + 6].hex(' ')}, not six NOPs"
    )
    assert repl[:idx] == want[:idx], f"{patch.id}: bytes before the call changed"
    assert repl[idx + 6 :] == want[idx + 6 :], f"{patch.id}: bytes after changed"


@pytest.mark.parametrize("patch", _patches(NAV_PATCH_IDS), ids=lambda p: p.id)
def test_nav_patch_prologue_is_the_shared_addwidget_shape(patch):
    """All five addWidget sites share a 12-byte prologue:

        45 8B CD        mov  r9d, r13d
        45 33 C0        xor  r8d, r8d
        49/48 8B Dx     mov  rdx, <widget>
        48 8B CE        mov  rcx, rsi
        FF 15 disp32    call [rip+disp32]   <- the 6 bytes NOPed

    That shared shape is why a signature alone cannot find them (the remote
    and feedback sites each match seven places in the image) and a `string-ref`
    locator on the widget's own object name is used instead.  Asserting it
    documents the constraint and catches a locator moved onto another call.
    """
    want = patcher.parse_hex_bytes(patch.expect)
    assert len(want) == 18
    assert want[0:5] == bytes.fromhex("458BCD4533"), want[0:5].hex(" ")
    assert want[5] == 0xC0, f"{patch.id}: expected C0 at 5, got {want[5]:#04x}"
    assert want[6] in (0x48, 0x49), f"{patch.id}: expected 48/49 at 6"
    assert (
        want[7:9] == bytes.fromhex("8BD3")
        or want[7:9] == bytes.fromhex("8BD4")
        or want[7:9] == bytes.fromhex("8BD7")
    ), want[7:9].hex(" ")
    assert want[9:12] == bytes.fromhex("488BCE"), want[9:12].hex(" ")
    assert want[12:14] == bytes.fromhex("FF15"), want[12:14].hex(" ")


def test_nav_patch_rvas_are_ascending_and_in_one_function():
    """All four addWidget sites sit in the rail builder 0x146b80-0x147900."""
    rvas = sorted(p.known_rvas[0] for p in _patches(NAV_PATCH_IDS))
    assert rvas == [0x146F6D, 0x14748F, 0x14779E]
    for r in rvas:
        assert 0x146B80 <= r <= 0x147900, f"{r:#x} is outside the rail builder"


def test_device_button_is_not_patched():
    """设备 is kept, so no patch may claim its addWidget site.

    leftDeviceBtn's addWidget is at 0x146c38, prologue 0x146c2c.  It is the
    button that opens the device list, which the user asked to retain.
    """
    forbidden = {0x146C2C, 0x146C38}
    for _, p in _all_patches():
        if p.target_rva is not None:
            assert p.target_rva not in forbidden, (
                f"{p.id} patches the 设备 (leftDeviceBtn) site {p.target_rva:#x}, which is kept"
            )


def test_lobster_button_is_not_patched():
    """leftLobsterBtn is not in the screenshot, so it must be left alone.

    Its addWidget is at 0x147200 (prologue 0x1471f4).  This matters because the
    build order is not the on-screen order: leftLobsterBtn is constructed
    before leftCloudPhoneBtn, so an address-order assumption silently targets
    the wrong button.  This test forbids both sites.
    """
    forbidden = {0x1471F4, 0x147200}
    for _, p in _all_patches():
        if p.target_rva is not None:
            assert p.target_rva not in forbidden, (
                f"{p.id} patches the leftLobsterBtn site {p.target_rva:#x}, which is not in scope"
            )


def test_tray_patch_exists_once():
    assert len(_patches({"tray-redemption-center"})) == 1


def test_tray_patch_makes_the_guard_unconditional():
    """The tray patch converts the entry's `je rel32` into a `jmp rel32`.

    The block already jumps to 0x10dbfc when its own predicate is false, so
    forcing the first guard to jump takes a path the binary already contains.
    The replacement must therefore be E9 + the same displacement target,
    padded with one NOP to keep the original 6-byte length.
    """
    patch = _patches({"tray-redemption-center"})[0]
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl)

    # The original conditional jump: 0F 84 rel32 at offsets 13..18.
    idx = want.find(bytes.fromhex("0F84"))
    assert idx == 13, f"unexpected je offset {idx:#x}"

    # Replacement: E9 (jmp rel32) + rel32 + one NOP.
    assert repl[idx] == 0xE9, f"expected E9 at {idx}, got {repl[idx]:#04x}"

    # The displacement *shifts by one* because `jmp` is 5 bytes and `je` is 6,
    # but both must resolve to the same destination address.  Asserting the
    # destination rather than the raw bytes is what actually matters.
    import struct as _struct

    base = patch.known_rvas[0]
    je_next = base + idx + 6
    je_target = je_next + _struct.unpack("<i", want[idx + 2 : idx + 6])[0]
    jmp_next = base + idx + 5
    jmp_target = jmp_next + _struct.unpack("<i", repl[idx + 1 : idx + 5])[0]
    assert je_target == jmp_target, (
        f"the jmp must land on the same skip target as the je ({jmp_target:#x} vs {je_target:#x})"
    )
    assert je_target == 0x10DBFC, f"unexpected skip target {je_target:#x}"
    assert repl[idx + 5] == 0x90, "the sixth byte must be a NOP to keep length"


def test_tray_patch_and_menu_patch_are_distinct():
    """The tray and dropdown 兑换中心 are different identifiers in different
    functions and need separate patches; neither may be dropped."""
    ids = {p.id for p in _load()["remove-components"].patches}
    assert "menu-redemption-center" in ids
    assert "tray-redemption-center" in ids


# --------------------------------------------------------------------------- #
# device-ui profile (MuMuNxDevice.exe)
# --------------------------------------------------------------------------- #
DEVICE_IDS = {
    "splash-carousel",
    "splash-ad-download",
    "splash-logo",
    "menu-remote-control",
    "menu-acceleration",
    "menu-dynamics-tab",
    "gametools-no-autopopup",
    "gametools-no-config-fetch",
}


def _device_patches():
    return _load()["device-ui"].patches


def test_device_patches_exist():
    assert {p.id for p in _device_patches()} == DEVICE_IDS


def test_device_profile_targets_the_device_binary():
    """All device-ui patches must name MuMuNxDevice.exe.

    It is a different executable from MuMuNxMain.exe, and an address from one
    is meaningless in the other.
    """
    for p in _device_patches():
        assert p.file.endswith("MuMuNxDevice.exe"), p.file
        assert "nx_device" in p.file, p.file


def test_remote_control_patch_skips_only_its_own_block():
    """远程控制 is unguarded, so the patch jumps over just that one item.

    The entry has no feature check around its construction -- the stub call in
    its block only guards an optional click handler, and that stub's `je` lands
    *before* the item factory.  The item is therefore always built, and the
    only way to remove it is to jump from its block start (0x254f9e) to the
    start of the next item's guard (0x25501b).

    The destination matters: jumping to 0x2555f1 lands *past* the 加速服务
    guard and silently removes two entries.  Landing on 0x25501b -- the
    `mov rcx,[r14+458h]` that opens the 加速服务 guard -- leaves every later
    entry alone.

    Layout of the replacement (16 bytes, same as the original):

        E9 <rel32>          jmp 0x25501b
        90 x 11             padding to keep the length
    """
    import struct as _struct

    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "menu-remote-control")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 28

    # The 16 bytes being overwritten start with lea rcx,[rbp+disp32].
    assert want[0:3] == bytes.fromhex("488D8D"), want[0:3].hex(" ")
    assert repl[0] == 0xE9, f"expected a jmp opcode, got {repl[0]:#04x}"
    assert repl[5:16] == b"\x90" * 11, "expected 11 NOPs of padding"
    # The literal tail (the signature's anchor) must be untouched.
    assert repl[16:] == want[16:], "the anchor bytes must not change"

    base = patch.known_rvas[0]
    dest = base + 5 + _struct.unpack("<i", repl[1:5])[0]
    assert dest == 0x25501B, (
        f"jmp lands on {dest:#x}; it must stop at the next item's guard "
        f"(0x25501b) or it will remove more than 远程控制"
    )


def test_acceleration_patch_forces_its_own_guard_branch():
    """加速服务 IS feature-gated, so the patch rewrites that gate's `je`.

    The gate is live:

        BA 2B 00 00 00   mov  edx, 2bh        ; feature id 43 = UU
        E8 ..            call IsFeatureEnabled
        84 C0            test al, al
        0F 84 ..         jz   <skip the item> ; <- rewritten

    Forcing the skip reuses an edge the binary already contains.  The
    replacement is the same length (5-byte jmp + 1 NOP for the 6-byte jz), and
    because the branch belongs to this item's own guard it cannot reach the
    following entry.
    """
    import struct as _struct

    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "menu-acceleration")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 18

    # The feature-id load, call and test must not move.
    assert want[0:5] == bytes.fromhex("BA2B000000"), want[0:5].hex(" ")
    assert want[5] == 0xE8, "expected the call opcode"
    assert repl[0:12] == want[0:12], "the mov/call/test prologue must not change"
    # The conditional jump becomes unconditional.
    assert want[12:14] == bytes.fromhex("0F84"), (
        f"expected jz rel32 (0F 84), got {want[12:14].hex(' ')}"
    )
    assert repl[12] == 0xE9, f"expected a jmp opcode, got {repl[12]:#04x}"
    assert repl[17] == 0x90, "the sixth byte must be a NOP to keep length"

    # Both the original jz and the new jmp must reach the same address.
    at = patch.target_rva + 12
    jz_target = at + 6 + _struct.unpack("<i", want[14:18])[0]
    jmp_target = at + 5 + _struct.unpack("<i", repl[13:17])[0]
    assert jz_target == 0x2555F1, f"unexpected original target {jz_target:#x}"
    assert jmp_target == jz_target, (
        f"jmp lands on {jmp_target:#x} but the original jz went to {jz_target:#x}"
    )


def test_device_menu_patches_leave_other_entries_alone():
    """Only 远程控制 and 加速服务 are in scope.

    The other side-panel entries have their own guard call sites; none may be
    claimed.  These are the call sites for the neighbouring blocks.
    """
    others = {
        0x251F00,  # android
        0x252D00,  # window manager
        0x254300,  # keymap
        0x254700,  # operation recorder
        0x254B00,  # synchronizer
        0x255900,  # gps
        0x255D00,  # multi player
        0x256100,  # game tools
        0x256400,  # more tools
    }
    for p in _device_patches():
        for bad in others:
            assert abs(p.target_rva - bad) > 0x80, (
                f"{p.id} at {p.target_rva:#x} is suspiciously close to the "
                f"out-of-scope block near {bad:#x}"
            )


def test_splash_patch_forces_the_existing_empty_bail_out():
    """The ad patch must rewrite the `jnz` in updateCarouselBkImages.

    This is the *display* path:

        FF 15 ..     call QListData::isEmpty     ; the candidate image list
        84 C0        test al, al
        0F 85 ..     jnz  <image info is empty>  ; <- rewritten

    The target is the author's own "nothing to show" tail, which drops the
    downloaded list and falls back to the built-in art.  Forcing it means the
    campaign never reaches the screen.

    `continueCarouselBkImages` (0x2a5400) is the decoy: it is only reached from
    `ShellWindow::gotoStartingPage` and Qt connection tables, never while the ad
    is displayed, so patching it leaves the ad on screen.  The test below pins
    the site to the function that actually runs.
    """
    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "splash-carousel")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 17

    # The isEmpty call and its test must not move.
    assert want[0:2] == bytes.fromhex("FF15"), want[0:2].hex(" ")
    assert want[6:8] == bytes.fromhex("84C0"), (
        f"expected test al,al (84 C0), got {want[6:8].hex(' ')}"
    )
    assert repl[0:8] == want[0:8], "the call/test prologue must not change"
    # The conditional jump becomes unconditional.
    assert want[8:10] == bytes.fromhex("0F85"), (
        f"expected jnz rel32 (0F 85), got {want[8:10].hex(' ')}"
    )
    assert repl[8] == 0xE9, f"expected a jmp opcode, got {repl[8]:#04x}"
    assert repl[13] == 0x90, "the sixth byte must be a NOP to keep length"
    # Everything after the rewritten jump is untouched.
    assert repl[14:] == want[14:], "the trailing bytes must not change"


def test_splash_patch_targets_the_display_path_not_the_hide_path():
    """The ad patch must edit updateCarouselBkImages (0x2a79b0).

    The two StartupBkWidget entry points have similar names and only one is on
    the ad-display path.  Patching the other one is a silent no-op.  The
    recorded RVA must therefore fall inside updateCarouselBkImages and well away
    from continueCarouselBkImages.
    """
    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "splash-carousel")

    update_carousel = 0x2A79B0  # the display path
    continue_carousel = 0x2A5400  # the hide path, reached only on shutdown
    assert update_carousel <= patch.target_rva < update_carousel + 0x400, (
        f"splash-carousel is at {patch.target_rva:#x}, outside "
        f"updateCarouselBkImages ({update_carousel:#x})"
    )
    assert abs(patch.target_rva - continue_carousel) > 0x1000, (
        "the patch has drifted back onto continueCarouselBkImages, which is "
        "not on the ad-display path"
    )


def test_ad_download_patch_forces_the_fetch_early_return():
    """The download patch must turn the fetch's own guard into a jmp.

    `StartupImageManager::fetchImageInfos_` (0x141023750) is the single entry
    point for the campaign request; stopping it there stops the HTTP GET, the
    JSON parse and the three JPEG downloads together.  The function already
    opens with a null-context guard:

        4C 39 B1 F0 00 00 00   cmp [rcx+0F0h], r14   ; r14 = 0
        0F 84 BB 14 00 00      jz  <epilogue>        ; <- rewritten
        0F 57 C0               xorps xmm0, xmm0

    Forcing it makes the fetch a no-op.  The replacement is the same length
    (5-byte jmp + 1 NOP for the 6-byte jz).
    """
    import struct as _struct

    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "splash-ad-download")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 16

    # The context comparison must not move.
    assert want[0:7] == bytes.fromhex("4C39B1F0000000"), want[0:7].hex(" ")
    assert repl[0:7] == want[0:7], "the cmp must not change"
    # The conditional jump becomes unconditional.
    assert want[7:9] == bytes.fromhex("0F84"), (
        f"expected jz rel32 (0F 84), got {want[7:9].hex(' ')}"
    )
    assert repl[7] == 0xE9, f"expected a jmp opcode, got {repl[7]:#04x}"
    assert repl[12] == 0x90, "the sixth byte must be a NOP to keep length"
    # Everything after the rewritten jump is untouched.
    assert repl[13:] == want[13:], "the trailing bytes must not change"

    # Both the original jz and the new jmp must reach the same epilogue.
    at = patch.target_rva + 7
    jz_target = at + 6 + _struct.unpack("<i", want[9:13])[0]
    jmp_target = at + 5 + _struct.unpack("<i", repl[8:12])[0]
    assert jz_target == 0x1024C62, f"unexpected original target {jz_target:#x}"
    assert jmp_target == jz_target, (
        f"jmp lands on {jmp_target:#x} but the original jz went to {jz_target:#x}"
    )


def test_ad_download_and_carousel_patches_are_independent():
    """Suppressing the download must not be conflated with hiding the image.

    They are different mechanisms in different modules -- `fetchImageInfos_` in
    StartupImageManager, `updateCarouselBkImages` in StartupBkWidget -- so each
    patch must claim its own address and either must stand alone.
    """
    prof = _load()["device-ui"]
    ids = {p.id for p in prof.patches}
    assert "splash-carousel" in ids
    assert "splash-ad-download" in ids

    carousel = next(p for p in prof.patches if p.id == "splash-carousel")
    download = next(p for p in prof.patches if p.id == "splash-ad-download")
    assert carousel.target_rva != download.target_rva
    assert abs(carousel.target_rva - download.target_rva) > 0x100000, (
        "the display path (0x2a79ec) and the fetch path (0x102379a) are in "
        "different modules; a small distance means one patch has drifted"
    )


def test_splash_logo_patch_forces_the_existing_skip_branch():
    """The logo patch must turn the author's own `jz` into an unconditional jmp.

    The site is the feature-51 gate:

        BA 33 00 00 00   mov  edx, 33h            ; StartupMiddleLogo
        E8 ..            call IsFeatureEnabled
        84 C0            test al, al
        0F 84 ..         jz   <skip the logo>     ; <- rewritten

    Taking the skip branch unconditionally reuses a path the binary already
    contains, so no new control flow is introduced.  The replacement is the
    same length (5-byte jmp + 1 NOP replaces the 6-byte jz).
    """
    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "splash-logo")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 21

    # The feature-id load and the call must not move.
    assert want[0:5] == bytes.fromhex("BA33000000"), want[0:5].hex(" ")
    assert want[5] == 0xE8, "expected the call opcode"
    assert repl[0:12] == want[0:12], "the mov/call/test prologue must not change"
    # The conditional jump becomes an unconditional one.
    assert want[12:14] == bytes.fromhex("0F84"), (
        f"expected jz rel32 (0F 84), got {want[12:14].hex(' ')}"
    )
    assert repl[12] == 0xE9, f"expected a jmp opcode, got {repl[12]:#04x}"
    assert repl[17] == 0x90, "the sixth byte must be a NOP to keep length"
    # Everything after the rewritten jump is untouched.
    assert repl[18:] == want[18:], "the trailing bytes must not change"


def test_splash_logo_patch_lands_on_the_original_target():
    """The new jmp must land exactly where the original jz went.

    Both are rel32 with different instruction lengths (6 vs 5), so the
    displacements differ; recomputing both from the same base is what proves
    the edge is the original one and not an approximation.
    """
    import struct as _struct

    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "splash-logo")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    base = patch.known_rvas[0]

    jz_at = base + 12
    jz_target = jz_at + 6 + _struct.unpack("<i", want[14:18])[0]
    jmp_at = base + 12
    jmp_target = jmp_at + 5 + _struct.unpack("<i", repl[13:17])[0]

    assert jz_target == 0x2A1F61, f"unexpected original target {jz_target:#x}"
    assert jmp_target == jz_target, (
        f"jmp lands on {jmp_target:#x} but the original jz went to {jz_target:#x}"
    )


def test_splash_logo_patch_is_not_the_splash_carousel_patch():
    """The two splash patches target different mechanisms and must not merge.

    `splash-carousel` stops downloaded campaign *ads*; `splash-logo` hides the
    built-in *logo*.  They sit in different functions, so neither may claim the
    other's address.
    """
    prof = _load()["device-ui"]
    ids = {p.id for p in prof.patches}
    assert "splash-carousel" in ids
    assert "splash-logo" in ids

    carousel = next(p for p in prof.patches if p.id == "splash-carousel")
    logo = next(p for p in prof.patches if p.id == "splash-logo")
    assert carousel.target_rva != logo.target_rva
    assert abs(carousel.target_rva - logo.target_rva) > 0x1000, (
        "the ad carousel and the logo live in different functions; a small "
        "distance means one patch has drifted onto the other's site"
    )


# --------------------------------------------------------------------------- #
# game tools panel (auto-popup, config fetch)
# --------------------------------------------------------------------------- #
def test_dynamics_tab_menu_patch_skips_only_its_own_block():
    """动态栏 is removed from the *menu*, by forcing its own feature gate.

    This is deliberately a different mechanism from the crashing
    `gametools-dynamics-tab` patch (see the test below): it forces a branch the
    binary already contains instead of making an object lookup fail.

    The guard, in the main-menu builder `sub_1402514A0`:

        0x255e76  mov  edx, 2ch            ; feature id 44
        0x255e7b  call Controller_IsFeatureEnabled
        0x255e80  test al, al
        0x255e82  jz   0x25629b            ; <-- forced here

    0x25629b is where the *first* `jz` of the same guard already lands, so the
    replacement walks a path the vendor wrote and exercises.  The skipped range
    builds only stack-local QStrings around the item factory, so jumping over it
    skips their constructors along with their destructors.
    """
    prof = _load()["device-ui"]
    by_id = {p.id: p for p in prof.patches}
    assert "menu-dynamics-tab" in by_id, "the 动态栏 menu patch is missing"

    p = by_id["menu-dynamics-tab"]
    assert p.target_rva == 0x255E76
    assert p.known_rvas == [0x255E76]

    # Same length in and out, so nothing relocates.
    assert len(p.replacement_bytes()) == len(p.parsed_signature().tokens) == 18

    # The signature pins the feature id and the call, but must wildcard every
    # byte the replacement overwrites -- otherwise the patch stops matching the
    # moment it is applied and `verify` reports it as lost.
    assert tuple(p.parsed_signature().tokens[:5]) == (0xBA, 0x2C, 0, 0, 0)
    assert p.expect is not None
    assert p.replacement_bytes()[12] == 0xE9, "expected an unconditional jmp"
    assert p.replacement_bytes()[17] == 0x90, "expected the trailing NOP"

    # 0x255e82 is the `jz`; a 5-byte `jmp rel32` reaches 0x25629b.
    jz_ea = 0x255E82
    rel = int.from_bytes(p.replacement_bytes()[13:17], "little")
    assert jz_ea + 5 + rel == 0x25629B


def test_dynamics_tab_patch_is_gone_and_must_not_come_back():
    """The 动态栏 tab must not be removed with the id-13 provider trick.

    NOPing the availability branch in the factory at 0x2cbd47 makes the object
    with id 13 disappear.  But id 13 is the 游戏中心 **toolbar button**, not a
    panel tab, and the title-bar builder dereferences the lookup result without
    a null check:

        0x140207f24  mov  edx, 0Dh        ; id 13
        0x140207f2c  call getObjectById   ; returns nullptr once id 13 is gone
        0x140207f31  mov  rcx, rax
        0x140207f34  call sub_14002784F   ; -> 0x2c6140: mov rax,[rcx+40h]

    The captured minidump: exception 0xC0000005, Rip = base+0x2c6140, Rcx = 0.

    This test is a guard rail: the patch must not be reintroduced without also
    handling the null lookup, and the profile must not claim it exists.

    Note the *menu* entry of the same name is removed by `menu-dynamics-tab`,
    which is a safe, different mechanism -- see the test above.  What is banned
    here is specifically the id-13 provider trick at 0x2cbd47.
    """
    prof = _load()["device-ui"]
    ids = {p.id for p in prof.patches}
    assert "gametools-dynamics-tab" not in ids, (
        "gametools-dynamics-tab crashes the device process on startup "
        "(null deref at RVA 0x2c6140); see the comment block in device-ui.toml"
    )

    # No patch may claim the old factory site -- that is the crashing trick.
    for p in prof.patches:
        assert p.target_rva != 0x2CBD47, f"{p.id} targets 0x2cbd47, the removed-and-crashing site"


def test_autopopup_patch_forces_the_display_epilogue():
    """The auto-popup is suppressed by forcing the GameToolsDisplay epilogue.

    The handler calls `SubShellWindow::showGameTools` and branches on its
    result:

        E8 ..            call showGameTools
        84 C0            test al, al
        0F 84 ..         jz   <epilogue>   ; <- rewritten

    Forcing the branch acknowledges the signal without building the window.
    """
    import struct as _struct

    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "gametools-no-autopopup")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 15

    # The call and the test must not move.
    assert want[0] == 0xE8, "expected the call opcode"
    assert want[5:7] == bytes.fromhex("84C0"), want[5:7].hex(" ")
    assert repl[0:7] == want[0:7], "the call/test prologue must not change"
    # The conditional jump becomes unconditional.
    assert want[7:9] == bytes.fromhex("0F84"), (
        f"expected jz rel32 (0F 84), got {want[7:9].hex(' ')}"
    )
    assert repl[7] == 0xE9, f"expected a jmp opcode, got {repl[7]:#04x}"
    assert repl[12] == 0x90, "the sixth byte must be a NOP to keep length"

    # Both the original jz and the new jmp must reach the same address.
    at = patch.target_rva + 7
    jz_target = at + 6 + _struct.unpack("<i", want[9:13])[0]
    jmp_target = at + 5 + _struct.unpack("<i", repl[8:12])[0]
    assert jz_target == 0x59ED92, f"unexpected original target {jz_target:#x}"
    assert jmp_target == jz_target, (
        f"jmp lands on {jmp_target:#x} but the original jz went to {jz_target:#x}"
    )


def test_autopopup_patch_does_not_touch_the_manual_button():
    """Only the automatic path may be patched; the toolbar button must survive.

    The automatic popup goes through `sub_14059EC10` (the GameToolsDisplay
    handler).  The manual route is `ShellWindow::triggerGameTools`
    (`sub_140284480`), a different function, so the two addresses must not
    collide.
    """
    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "gametools-no-autopopup")
    auto_handler = 0x59EC10
    manual_trigger = 0x284480
    assert auto_handler <= patch.target_rva < auto_handler + 0x400, (
        f"patch is at {patch.target_rva:#x}, outside the auto-popup handler ({auto_handler:#x})"
    )
    assert abs(patch.target_rva - manual_trigger) > 0x10000, (
        "the patch has drifted onto ShellWindow::triggerGameTools, which would "
        "break the manual 游戏中心 button too"
    )


def test_config_fetch_patch_forces_the_no_fetch_early_out():
    """The sidebar config download is stopped at its only caller's guard.

    `GameToolsPresenter::fetchGameToolsConfig` opens with:

        45 84 C9         test r9b, r9b      ; caller's "should fetch" flag
        0F 84 ..         jz   <bare ret>    ; <- rewritten
        53 56 57 ...     push ...           ; build and send the request

    The target is a bare `ret` reached before any push, so it is stack-safe.
    """
    import struct as _struct

    prof = _load()["device-ui"]
    patch = next(p for p in prof.patches if p.id == "gametools-no-config-fetch")
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 12

    assert want[0:3] == bytes.fromhex("4584C9"), want[0:3].hex(" ")
    assert repl[0:3] == want[0:3], "the test must not change"
    assert want[3:5] == bytes.fromhex("0F84"), (
        f"expected jz rel32 (0F 84), got {want[3:5].hex(' ')}"
    )
    assert repl[3] == 0xE9, f"expected a jmp opcode, got {repl[3]:#04x}"
    assert repl[8] == 0x90, "the sixth byte must be a NOP to keep length"
    assert repl[9:] == want[9:], "the trailing push prologue must not change"

    at = patch.target_rva + 3
    jz_target = at + 6 + _struct.unpack("<i", want[5:9])[0]
    jmp_target = at + 5 + _struct.unpack("<i", repl[4:8])[0]
    assert jz_target == 0xBCC0D1, f"unexpected original target {jz_target:#x}"
    assert jmp_target == jz_target, (
        f"jmp lands on {jmp_target:#x} but the original jz went to {jz_target:#x}"
    )


def test_gametools_patches_are_independent():
    """The tab, the popup and the fetch are three separate levers.

    They live in two different functions and each must be individually
    applicable -- suppressing the popup should not require killing the fetch,
    and vice versa.
    """
    prof = _load()["device-ui"]
    ids = {p.id for p in prof.patches}
    for want in ("gametools-no-autopopup", "gametools-no-config-fetch"):
        assert want in ids, want

    rvas = {}
    for pid in ("gametools-no-autopopup", "gametools-no-config-fetch"):
        p = next(x for x in prof.patches if x.id == pid)
        rvas[pid] = p.target_rva
    assert len(set(rvas.values())) == 2, f"duplicate sites: {rvas}"
    # They are in two different functions, so far apart in the image.
    ordered = sorted(rvas.values())
    for a, b in pairwise(ordered):
        assert b - a > 0x1000, f"{a:#x} and {b:#x} are too close to be different functions"


# --------------------------------------------------------------------------- #
# no-integrity-punish profile (MuMuNxMain.exe)
# --------------------------------------------------------------------------- #
INTEGRITY_IDS = {"integrity-check-clean-exit"}


def _integrity_patches() -> list[patcher.Patch]:
    return _load()["no-integrity-punish"].patches


def test_integrity_patches_exist():
    assert {p.id for p in _integrity_patches()} == INTEGRITY_IDS


def test_integrity_profile_targets_the_main_binary():
    for p in _integrity_patches():
        assert p.file == "nx_main/MuMuNxMain.exe", p.file


def test_integrity_patch_defuses_both_guards():
    """The condition is `!A || !B`, so BOTH branches must be defused.

    sub_1407198B0 decides whether to punish:

        1407198e8  test al, al
        1407198ea  jz   loc_140719900      ; guard 1: if !A -> punish
        1407198ec  lea  rdx, [rbp+var_50]
        1407198f0  mov  rcx, [rbx]
        1407198f3  call sub_14002DCA4      ; B: signer-name check -> al
        1407198f8  test al, al
        1407198fa  jnz  loc_140719BB0      ; guard 2: if B -> clean exit
        140719900  loc_140719900:          ; the punishment block
        ...
        140719bb0  loc_140719BB0:          ; the clean epilogue

    Patching only guard 2 is a no-op: a stripped binary fails A, and guard 1
    reaches the punishment block on its own.  That was a real regression -- the
    profile was applied and the CPU burn continued.  This test pins both edits.

    Guard 1 is removed (never punish) and guard 2 is made unconditional (always
    exit), so the block is unreachable for every combination of A and B, and
    control simply falls through to the epilogue.  Neither jump needs the other
    to be correct, which is why the assertion checks them independently.
    """
    import struct as _struct

    patch = _integrity_patches()[0]
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 22

    # --- guard 1: `jz loc_140719900` becomes two NOPs ---------------------
    assert want[0:2] == bytes.fromhex("7414"), (
        f"expected jz rel8 (74 14) at 0, got {want[0:2].hex(' ')}"
    )
    assert repl[0:2] == bytes.fromhex("9090"), (
        f"guard 1 must be NOPed out, got {repl[0:2].hex(' ')}"
    )
    at1 = patch.locate_rva
    jz_target = at1 + 2 + _struct.unpack("<b", want[1:2])[0]
    assert jz_target == 0x719900, f"unexpected guard-1 target {jz_target:#x}"

    # --- the middle is context and must not move --------------------------
    assert want[2:16] == bytes.fromhex("488D55B0488B0BE8AC4391FF84C0"), want[2:16].hex(" ")
    assert repl[2:16] == want[2:16], "the lea/mov/call/test must not change"

    # --- guard 2: `jnz loc_140719BB0` becomes an unconditional jmp --------
    assert want[16:18] == bytes.fromhex("0F85"), (
        f"expected jnz rel32 (0F 85) at 16, got {want[16:18].hex(' ')}"
    )
    assert repl[16] == 0xE9, f"expected a jmp opcode, got {repl[16]:#04x}"
    assert repl[21] == 0x90, "the sixth byte must be a NOP to keep length"

    at2 = patch.locate_rva + 16
    jnz_target = at2 + 6 + _struct.unpack("<i", want[18:22])[0]
    jmp_target = at2 + 5 + _struct.unpack("<i", repl[17:21])[0]
    assert jnz_target == 0x719BB0, f"unexpected original target {jnz_target:#x}"
    assert jmp_target == jnz_target, (
        f"jmp lands on {jmp_target:#x} but the original jnz went to {jnz_target:#x}"
    )

    # The two guards must point at the two different destinations; if they ever
    # converged the `!A || !B` shape would have been misread.
    assert jz_target != jnz_target, "guard 1 and guard 2 must lead to different blocks"


def test_integrity_patch_does_not_touch_the_check_itself():
    """Only the two branches are patched; the verification must still run.

    The predicates are sub_140024906 (WinVerifyTrust) and sub_14002DCA4 (the
    signer-name check).  Neither call may be NOPed or redirected -- the point is to
    ignore a negative verdict, not to stop looking.
    """
    import struct as _struct

    patch = _integrity_patches()[0]
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()

    # The signer-name call sits inside the patched window and must survive.
    assert want[9] == 0xE8, "the call to the signer-name predicate must not be modified"
    assert want[10:14] == bytes.fromhex("AC4391FF"), want[10:14].hex(" ")
    assert repl[9:14] == want[9:14], "the signer-name call must not change"

    at = patch.target_rva + 9
    assert at + 5 + _struct.unpack("<i", want[10:14])[0] == 0x2DCA4, (
        "the patched window no longer contains the call to sub_14002DCA4"
    )


def test_integrity_patch_site_is_the_check_not_a_lookalike():
    """The site must be inside sub_1407198B0.

    `test al,al` followed by a conditional jump is one of the most common
    shapes in the image (a bare `84 C0` scan finds hundreds of hits), so this
    asserts the anchor really landed on the integrity check rather than on a
    byte-identical neighbour.
    """
    patch = _integrity_patches()[0]
    assert 0x7198B0 <= patch.target_rva < 0x7198B0 + 0x327, (
        f"{patch.target_rva:#x} is outside sub_1407198B0"
    )
    # The window must end before the punishment block begins.
    assert patch.target_rva + len(patch.replacement_bytes()) <= 0x719900, (
        "the patched window must not reach into the punishment block"
    )


def test_integrity_profile_is_not_a_duplicate_of_the_others():
    """The integrity patch must be its own site, in its own region.

    It lives at 0x719xxx; the other main-process profiles are at 0x4exxx,
    0xc9cxxx, 0xe81xxx, 0x10d8e7, 0x146xxx, 0x14axxx and 0x168xxx-0x169xxx.
    """
    patch = _integrity_patches()[0]
    for _, other in _all_patches():
        if other.target_rva is None or other.id == patch.id:
            continue
        assert abs(other.target_rva - patch.target_rva) > 0x1000, (
            f"{other.id} at {other.target_rva:#x} collides with the integrity "
            f"patch at {patch.target_rva:#x}"
        )


# --------------------------------------------------------------------------- #
# no-device-integrity-punish profile (MuMuNxDevice.exe)
# --------------------------------------------------------------------------- #
DEVICE_INTEGRITY_IDS = {"device-integrity-check-clean-exit"}


def _device_integrity_patches() -> list[patcher.Patch]:
    return _load()["no-device-integrity-punish"].patches


def test_device_integrity_patches_exist():
    assert {p.id for p in _device_integrity_patches()} == DEVICE_INTEGRITY_IDS


def test_device_integrity_profile_targets_the_device_binary():
    for p in _device_integrity_patches():
        assert p.file == "nx_device/15.0/shell/MuMuNxDevice.exe", p.file


def test_device_integrity_patch_defuses_both_guards():
    """The condition is `!A || !B`, so BOTH branches must be defused.

    sub_1408DEF90 decides whether to punish:

        1408defc8  test al, al
        1408defca  jz   loc_1408DEFE0      ; guard 1: if !A -> punish
        1408defcc  lea  rdx, [rbp+var_50]
        1408defd0  mov  rcx, [rbx]
        1408defd3  call sub_14003644E      ; B: signer-name check -> al
        1408defd8  test al, al
        1408defda  jnz  loc_1408DF290      ; guard 2: if B -> clean exit
        1408defe0  loc_1408DEFE0:          ; the punishment block
        ...
        1408df290  loc_1408DF290:          ; the clean epilogue

    This is the same shape as the MuMuNxMain.exe check, and the same trap
    applies: patching only guard 2 is a no-op, because a stripped binary fails A
    and guard 1 reaches the punishment block on its own.

    Guard 1 is removed (never punish) and guard 2 is made unconditional (always
    exit), so the block is unreachable for every combination of A and B, and
    control simply falls through to the epilogue.  Neither jump needs the other
    to be correct, which is why the assertion checks them independently.
    """
    import struct as _struct

    patch = _device_integrity_patches()[0]
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()
    assert len(want) == len(repl) == 22

    # --- guard 1: `jz loc_1408DEFE0` becomes two NOPs ---------------------
    assert want[0:2] == bytes.fromhex("7414"), (
        f"expected jz rel8 (74 14) at 0, got {want[0:2].hex(' ')}"
    )
    assert repl[0:2] == bytes.fromhex("9090"), (
        f"guard 1 must be NOPed out, got {repl[0:2].hex(' ')}"
    )
    at1 = patch.target_rva
    jz_target = at1 + 2 + _struct.unpack("<b", want[1:2])[0]
    assert jz_target == 0x8DEFE0, f"unexpected guard-1 target {jz_target:#x}"

    # --- the middle is context and must not move --------------------------
    assert want[2:16] == bytes.fromhex("488D55B0488B0BE8767475FF84C0"), want[2:16].hex(" ")
    assert repl[2:16] == want[2:16], "the lea/mov/call/test must not change"

    # --- guard 2: `jnz loc_1408DF290` becomes an unconditional jmp --------
    assert want[16:18] == bytes.fromhex("0F85"), (
        f"expected jnz rel32 (0F 85) at 16, got {want[16:18].hex(' ')}"
    )
    assert repl[16] == 0xE9, f"expected a jmp opcode, got {repl[16]:#04x}"
    assert repl[21] == 0x90, "the sixth byte must be a NOP to keep length"

    at2 = patch.target_rva + 16
    jnz_target = at2 + 6 + _struct.unpack("<i", want[18:22])[0]
    jmp_target = at2 + 5 + _struct.unpack("<i", repl[17:21])[0]
    assert jnz_target == 0x8DF290, f"unexpected original target {jnz_target:#x}"
    assert jmp_target == jnz_target, (
        f"jmp lands on {jmp_target:#x} but the original jnz went to {jnz_target:#x}"
    )

    # The two guards must point at the two different destinations; if they ever
    # converged the `!A || !B` shape would have been misread.
    assert jz_target != jnz_target, "guard 1 and guard 2 must lead to different blocks"


def test_device_integrity_patch_does_not_touch_the_check_itself():
    """Only the two branches are patched; the verification must still run.

    The predicates are sub_14002B3FA (WinVerifyTrust, via sub_1408E2B60) and
    sub_14003644E (the signer-name check, via sub_1408E2C60).  Neither call may be
    NOPed or redirected -- the point is to ignore a negative verdict, not to
    stop looking.
    """
    import struct as _struct

    patch = _device_integrity_patches()[0]
    want = patcher.parse_hex_bytes(patch.expect)
    repl = patch.replacement_bytes()

    # The signer-name call sits inside the patched window and must survive.
    assert want[9] == 0xE8, "the call to the signer-name predicate must not be modified"
    assert want[10:14] == bytes.fromhex("767475FF"), want[10:14].hex(" ")
    assert repl[9:14] == want[9:14], "the signer-name call must not change"

    at = patch.target_rva + 9
    assert at + 5 + _struct.unpack("<i", want[10:14])[0] == 0x3644E, (
        "the patched window no longer contains the call to sub_14003644E"
    )


def test_device_integrity_patch_site_is_the_check_not_a_lookalike():
    """The site must be inside sub_1408DEF90, before the punishment block.

    `test al,al` followed by a conditional jump is one of the most common shapes
    in the image, so this asserts the locator really landed on the integrity
    check rather than on a byte-identical neighbour.
    """
    patch = _device_integrity_patches()[0]
    assert 0x8DEF90 <= patch.target_rva < 0x8DEF90 + 0x327, (
        f"{patch.target_rva:#x} is outside sub_1408DEF90"
    )
    # The window must end before the punishment block begins.
    assert patch.target_rva + len(patch.replacement_bytes()) <= 0x8DEFE0, (
        "the patched window must not reach into the punishment block"
    )


def test_device_integrity_patch_locates_semantically_not_by_rva():
    """Unlike its MuMuNxMain.exe counterpart, this one has a usable anchor.

    The check opens by calling `QCoreApplication::applicationFilePath`, a plain
    import call, and the patched window begins 0x15 bytes later.  So the site is
    found from a fact that survives a rebuild, and no build-specific number is
    pinned.  MuMuNxMain.exe's equivalent cannot do this because its predicate
    resolves `WinVerifyTrust` through a pointer loaded at run time, which puts
    the symbol in no import table.

    This is asserted rather than left to `test_robustness.py` because it is the
    reason the two profiles differ in shape, and a future edit that "simplifies"
    this one to match the other would silently give up the property.
    """
    patch = _device_integrity_patches()[0]
    assert patch.locate is not None, "the device patch must use a semantic locator"
    assert patch.locate.kind == "import-call", patch.locate.kind
    assert "applicationFilePath" in patch.locate.value, patch.locate.value
    assert patch.locate_rva is None, "locate_rva would make this patch build-specific for no reason"
    assert not patch.is_build_specific(), patch.resolver()
    # The anchor sits 0x15 bytes before the window, so the window has to cover
    # that gap plus the anchor instruction itself.
    assert patch.locate.window >= 0x15, patch.locate.window


def test_device_integrity_signature_keeps_the_call_displacement_literal():
    """The signer-name `call` displacement must stay pinned in the signature.

    Every byte the patch overwrites is a wildcard, but the call in the middle is
    context.  Wildcarding its displacement as well makes the pattern match a
    second site at RVA 0x8defba -- a nearby `lea`/`call`/`test` sequence -- and
    `scan_unique` would then refuse the patch as ambiguous.  The locator finds
    the site, so the signature only has to verify it; keeping the displacement
    literal is what makes that verification unambiguous.
    """
    patch = _device_integrity_patches()[0]
    sig = patch.parsed_signature()
    assert sig.tokens[9] == 0xE8, "the call opcode must be pinned"
    assert sig.tokens[10:14] == (0x76, 0x74, 0x75, 0xFF), sig.tokens[10:14]
    # The guards, and only the guards, are wildcards.
    wild = {i for i, t in enumerate(sig.tokens) if t is None}
    assert wild == {0, 1, 16, 17, 18, 19, 20, 21}, sorted(wild)


def test_device_integrity_profile_is_not_a_duplicate_of_the_others():
    """The device integrity patch must be its own site, in its own region.

    It lives at 0x8dexxx; the `device-ui` patches are at 0x254xxx, 0x255xxx,
    0x2a1xxx, 0x2a7xxx, 0x59exxx, 0xbcbxxx and 0x1023xxx.
    """
    patch = _device_integrity_patches()[0]
    for _, other in _all_patches():
        if other.target_rva is None or other.id == patch.id:
            continue
        if other.file != patch.file:
            continue
        assert abs(other.target_rva - patch.target_rva) > 0x1000, (
            f"{other.id} at {other.target_rva:#x} collides with the device "
            f"integrity patch at {patch.target_rva:#x}"
        )


# --------------------------------------------------------------------------- #
# no-device-telemetry profile (MuMuNxDevice.exe)
# --------------------------------------------------------------------------- #
DEVICE_TELEMETRY_IDS = {"sensors-host", "nxsensors-host"}


def _device_telemetry_patches() -> list[patcher.Patch]:
    return _load()["no-device-telemetry"].patches


def test_device_telemetry_patches_exist():
    assert {p.id for p in _device_telemetry_patches()} == DEVICE_TELEMETRY_IDS


def test_device_telemetry_profile_targets_the_device_binary():
    for p in _device_telemetry_patches():
        assert p.file == "nx_device/15.0/shell/MuMuNxDevice.exe", p.file


def test_device_telemetry_requires_the_integrity_fix():
    """Patching this binary arms the CPU-burn trap; the dependency must be declared."""
    assert _load()["no-device-telemetry"].requires == ["no-device-integrity-punish"]


def test_device_telemetry_rewrites_both_url_branches():
    """Each window must cover the test AND prod `lea`, so neither survives.

    The code picks its endpoint as:

        lea rax, [test]      ; 48 8D 05 <disp32>
        lea rdx, [prod]      ; 48 8D 15 <disp32>
        test ebx, ebx
        cmovnz rdx, rax

    so `sensors_debug` in the registry chooses between them at run time.
    Rewriting only the production `lea` -- which is what the MuMuNxMain.exe
    profile does -- leaves a machine with that value set still reporting.  Both
    displacements have to move, and this asserts the window spans both.
    """
    import struct as _struct

    for patch in _device_telemetry_patches():
        want = patcher.parse_hex_bytes(patch.expect)
        repl = patch.replacement_bytes()
        assert len(want) == len(repl) == 18, patch.id

        # the two lea opcodes and the shared tail
        assert want[0:3] == bytes.fromhex("488D05"), want[0:3].hex(" ")
        assert want[7:10] == bytes.fromhex("488D15"), want[7:10].hex(" ")
        assert want[14:18] == bytes.fromhex("85DB480F"), want[14:18].hex(" ")

        # opcodes and tail are context; only the displacements may change
        assert repl[0:3] == want[0:3] and repl[7:10] == want[7:10]
        assert repl[14:18] == want[14:18]

        # both displacements must have been rewritten
        assert repl[3:7] != want[3:7], f"{patch.id}: lea rax displacement unchanged"
        assert repl[10:14] != want[10:14], f"{patch.id}: lea rdx displacement unchanged"

        # and both must land on the same empty byte
        rax = patch.target_rva + 7 + _struct.unpack("<i", repl[3:7])[0]
        rdx = patch.target_rva + 7 + 7 + _struct.unpack("<i", repl[10:14])[0]
        assert rax == rdx, (
            f"{patch.id}: lea rax -> {rax:#x} but lea rdx -> {rdx:#x}; they must "
            f"agree or one branch keeps a live endpoint"
        )


def test_device_telemetry_signature_wildcards_only_the_displacements():
    """The two `lea` displacements are rewritten, so they must be wildcards."""
    for patch in _device_telemetry_patches():
        sig = patch.parsed_signature()
        wild = {i for i, t in enumerate(sig.tokens) if t is None}
        assert wild == {3, 4, 5, 6, 10, 11, 12, 13}, (patch.id, sorted(wild))


def test_device_telemetry_locators_use_the_registry_keys():
    """The anchors must be the per-function registry keys, not the URLs.

    Each endpoint URL is referenced once per function, so `resolve` -- which
    unions the sites found near *every* anchor -- would see two candidates and
    refuse the patch as ambiguous.  The registry keys are opened by exactly one
    function each, which is what makes them usable as discriminators.
    """
    patches = {p.id: p for p in _device_telemetry_patches()}
    for pid, key in (
        ("sensors-host", "MuMuPlayer"),
        ("nxsensors-host", "MuMuNx"),
    ):
        loc = patches[pid].locate
        assert loc is not None and loc.kind == "string-ref", (pid, loc)
        assert key in loc.value, (pid, loc.value)
        assert loc.value.startswith("HKEY_CURRENT_USER\\Software\\Netease\\"), loc.value
        assert patches[pid].locate_rva is None, pid
        assert not patches[pid].is_build_specific(), pid


def test_device_telemetry_patches_are_independent():
    """The two hosts are separate levers in separate functions."""
    patches = sorted(_device_telemetry_patches(), key=lambda p: p.target_rva)
    rvas = [p.target_rva for p in patches]
    assert len(set(rvas)) == 2, rvas
    assert rvas[1] - rvas[0] > 0x20, (
        f"{rvas[0]:#x} and {rvas[1]:#x} are too close to be separate sites"
    )
    # And neither window may overlap the other.
    for a, b in pairwise(patches):
        assert a.target_rva + len(a.replacement_bytes()) <= b.target_rva, (a.id, b.id)


def test_device_telemetry_does_not_touch_the_integrity_patch():
    """The telemetry and integrity fixes are different sites in different functions."""
    for p in _device_telemetry_patches():
        for q in _device_integrity_patches():
            assert abs(p.target_rva - q.target_rva) > 0x1000, (p.id, q.id)


# --------------------------------------------------------------------------- #
# no-telemetry profile (MuMuNxMain.exe) -- the two Sensors hosts
# --------------------------------------------------------------------------- #
MAIN_TELEMETRY_IDS = {"shence-endpoint", "gearup-endpoint", "crashrpt-endpoint"}


def _main_telemetry_patches() -> list[patcher.Patch]:
    return _load()["no-telemetry"].patches


def test_main_telemetry_patches_exist():
    assert {p.id for p in _main_telemetry_patches()} == MAIN_TELEMETRY_IDS


def test_main_telemetry_profile_targets_the_main_binary():
    for p in _main_telemetry_patches():
        assert p.file == "nx_main/MuMuNxMain.exe", p.file


def test_main_telemetry_rewrites_both_url_branches():
    """The two Sensors hosts must cover test AND prod, or `sensors_debug` bypasses them.

    Each `UrlManager` accessor picks its endpoint at run time:

        lea rax, [test]      ; 48 8D 05 <disp32>
        lea rdx, [prod]      ; 48 8D 15 <disp32>
        test ebx, ebx
        cmovnz rdx, rax      ; sensors_debug != 0 -> test

    Rewriting only the production `lea` is enough on a default install, because
    `sensors_debug` is normally unset -- but it leaves a machine with that value
    set still reporting.  Both displacements must move, in one window.

    `crashrpt-endpoint` is deliberately excluded: it is a different shape (no
    `cmovnz`), so there is no second branch to cover.
    """
    import struct as _struct

    dual = [p for p in _main_telemetry_patches() if p.id != "crashrpt-endpoint"]
    assert {p.id for p in dual} == {"shence-endpoint", "gearup-endpoint"}

    for patch in dual:
        want = patcher.parse_hex_bytes(patch.expect)
        repl = patch.replacement_bytes()
        assert len(want) == len(repl) == 18, patch.id

        assert want[0:3] == bytes.fromhex("488D05"), want[0:3].hex(" ")
        assert want[7:10] == bytes.fromhex("488D15"), want[7:10].hex(" ")
        assert want[14:18] == bytes.fromhex("85DB480F"), want[14:18].hex(" ")

        assert repl[0:3] == want[0:3] and repl[7:10] == want[7:10]
        assert repl[14:18] == want[14:18]

        assert repl[3:7] != want[3:7], f"{patch.id}: lea rax displacement unchanged"
        assert repl[10:14] != want[10:14], f"{patch.id}: lea rdx displacement unchanged"

        rax = patch.target_rva + 7 + _struct.unpack("<i", repl[3:7])[0]
        rdx = patch.target_rva + 14 + _struct.unpack("<i", repl[10:14])[0]
        assert rax == rdx, (
            f"{patch.id}: lea rax -> {rax:#x} but lea rdx -> {rdx:#x}; they must "
            f"agree or one branch keeps a live endpoint"
        )


def test_main_telemetry_locators_survive_their_own_patch():
    """The anchors must be things the patch does not destroy.

    This is the constraint that forces the registry keys.  Anchoring on the
    endpoint URL is the obvious choice and it is wrong for a dual-branch patch:
    the URL is referenced only by the `lea` the patch rewrites, so after
    applying, `resolve` finds no anchor at all -- `verify` reports the patch
    lost and a re-run cannot find the site.  Each accessor opens its own
    registry key, which the patch never touches.
    """
    keys = {
        "shence-endpoint": "MuMuPlayer",
        "gearup-endpoint": "MuMuNx",
    }
    for pid, key in keys.items():
        patch = next(p for p in _main_telemetry_patches() if p.id == pid)
        loc = patch.locate
        assert loc is not None and loc.kind == "string-ref", (pid, loc)
        assert key in loc.value, (pid, loc.value)
        assert loc.value.startswith("HKEY_CURRENT_USER\\Software\\Netease\\"), loc.value
        # and the anchor must not be inside the window the patch rewrites
        assert "shence-api" not in loc.value and "gearupportal" not in loc.value
        assert patch.locate_rva is None, pid
        assert not patch.is_build_specific(), pid


def test_main_telemetry_signature_wildcards_only_the_displacements():
    for patch in _main_telemetry_patches():
        if patch.id == "crashrpt-endpoint":
            continue
        sig = patch.parsed_signature()
        wild = {i for i, t in enumerate(sig.tokens) if t is None}
        assert wild == {3, 4, 5, 6, 10, 11, 12, 13}, (patch.id, sorted(wild))


def test_main_telemetry_patches_are_independent():
    """Three separate endpoints, three separate sites."""
    patches = sorted(_main_telemetry_patches(), key=lambda p: p.target_rva)
    rvas = [p.target_rva for p in patches]
    assert len(set(rvas)) == 3, rvas
    for a, b in pairwise(patches):
        assert a.target_rva + len(a.replacement_bytes()) <= b.target_rva, (a.id, b.id)


def test_main_telemetry_requires_the_integrity_fix():
    """Patching this binary arms the CPU-burn trap; the dependency must be declared."""
    assert _load()["no-telemetry"].requires == ["no-integrity-punish"]
