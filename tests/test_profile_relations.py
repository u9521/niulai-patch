"""Tests for profile-level relations: ``requires`` and ``build``.

``requires`` exists because of a real incident, so the tests here are written
around the incident rather than around the data structure: the profile that
disarms MuMuNxMain.exe's self-integrity check must not be forgettable.
"""

from __future__ import annotations

import pytest

from pe import patcher


def _write(tmp_path, name: str, body: str):
    (tmp_path / f"{name}.toml").write_text(body, encoding="utf-8")


def _minimal(name: str, *, requires: str = "", build: str = "", file: str = "a.exe") -> str:
    lines = ["[profile]", f'name = "{name}"', 'description = "d"']
    if requires:
        lines.append(requires)
    if build:
        lines.append(build)
    lines += [
        "[[patch]]",
        f'id = "{name}-p"',
        'description = "p"',
        f'file = "{file}"',
        'signature = "48 8B 05 ?? ?? ?? ??"',
        'replace = "48 8B 05 11 22 33 44"',
        'expect = "48 8B 05 DE AD BE EF"',
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# requires
# --------------------------------------------------------------------------- #
def test_requires_parses(tmp_path):
    _write(tmp_path, "base", _minimal("base"))
    _write(tmp_path, "user", _minimal("user", requires='requires = ["base"]'))
    profiles = patcher.load_profiles(tmp_path)
    assert profiles["user"].requires == ["base"]
    assert profiles["base"].requires == []


def test_missing_requirement_is_a_load_error(tmp_path):
    """Fail at load time, not halfway through a run with files already written."""
    _write(tmp_path, "user", _minimal("user", requires='requires = ["ghost"]'))
    with pytest.raises(patcher.PatchError, match="do not exist"):
        patcher.load_profiles(tmp_path)


def test_self_requirement_is_rejected(tmp_path):
    _write(tmp_path, "loop", _minimal("loop", requires='requires = ["loop"]'))
    with pytest.raises(patcher.PatchError, match="requires itself"):
        patcher.load_profiles(tmp_path)


def test_resolve_requirements_puts_dependencies_first(tmp_path):
    _write(tmp_path, "base", _minimal("base"))
    _write(tmp_path, "mid", _minimal("mid", requires='requires = ["base"]'))
    _write(tmp_path, "top", _minimal("top", requires='requires = ["mid"]'))
    profiles = patcher.load_profiles(tmp_path)
    assert patcher.resolve_requirements(profiles, ["top"]) == ["base", "mid", "top"]


def test_resolve_requirements_does_not_duplicate(tmp_path):
    _write(tmp_path, "base", _minimal("base"))
    _write(tmp_path, "a", _minimal("a", requires='requires = ["base"]'))
    _write(tmp_path, "b", _minimal("b", requires='requires = ["base"]'))
    profiles = patcher.load_profiles(tmp_path)
    got = patcher.resolve_requirements(profiles, ["a", "b"])
    assert got == ["base", "a", "b"]


def test_resolve_requirements_passes_unknown_names_through(tmp_path):
    """The caller reports unknown names; silently dropping them would hide a typo."""
    _write(tmp_path, "base", _minimal("base"))
    profiles = patcher.load_profiles(tmp_path)
    assert patcher.resolve_requirements(profiles, ["nope"]) == ["nope"]


def test_resolve_requirements_detects_a_cycle(tmp_path):
    """A cycle cannot exist through ``load_profiles`` (self-requires is caught),
    but the resolver is a public function and must not loop forever."""
    profiles = {
        "a": patcher.Profile("a", "", [], requires=["b"]),
        "b": patcher.Profile("b", "", [], requires=["a"]),
    }
    with pytest.raises(patcher.PatchError, match="cycle"):
        patcher.resolve_requirements(profiles, ["a"])


# --------------------------------------------------------------------------- #
# the real profiles
# --------------------------------------------------------------------------- #
def test_every_main_binary_profile_requires_the_integrity_fix():
    """The incident, encoded.

    Any patch to MuMuNxMain.exe strips its Authenticode blob, which arms a
    self-integrity check that spawns CPU-burning threads.  Every profile
    targeting that binary must therefore declare the profile that defuses it.
    """
    profiles = patcher.load_profiles()
    trap = "no-integrity-punish"
    for name, prof in profiles.items():
        if name == trap:
            continue
        if any(p.file == "nx_main/MuMuNxMain.exe" for p in prof.patches):
            assert trap in prof.requires, (
                f"{name} patches MuMuNxMain.exe but does not require {trap!r}; "
                f"applying it alone arms the CPU-burn trap"
            )


def test_every_device_binary_profile_requires_the_integrity_fix():
    """The same incident, on the other binary.

    MuMuNxDevice.exe carries its own copy of the self-integrity check -- a
    separate one from MuMuNxMain.exe's, with unrelated addresses.  A live
    patched process was caught burning a full core with eleven detached sqrt
    threads, so patching this binary alone arms the same trap.
    """
    profiles = patcher.load_profiles()
    trap = "no-device-integrity-punish"
    for name, prof in profiles.items():
        if name == trap:
            continue
        if any(p.file == "nx_device/15.0/shell/MuMuNxDevice.exe" for p in prof.patches):
            assert trap in prof.requires, (
                f"{name} patches MuMuNxDevice.exe but does not require {trap!r}; "
                f"applying it alone arms the CPU-burn trap"
            )


def test_the_integrity_profiles_require_nothing():
    """They are the bases of the dependency graph; requiring anything would be a
    cycle.  One per binary: the two checks are independent, and neither profile's
    patch works in the other binary."""
    profiles = patcher.load_profiles()
    assert profiles["no-integrity-punish"].requires == []
    assert profiles["no-device-integrity-punish"].requires == []


def test_the_two_integrity_profiles_target_different_binaries():
    """Pin the separation, so a copy-paste between them is caught.

    The two profiles are near-identical in shape and the device one was authored
    by adapting the main one, which is exactly the situation where a stale
    `file =` line survives review.  Neither patch's bytes mean anything in the
    other binary.
    """
    profiles = patcher.load_profiles()
    main = {p.file for p in profiles["no-integrity-punish"].patches}
    device = {p.file for p in profiles["no-device-integrity-punish"].patches}
    assert main == {"nx_main/MuMuNxMain.exe"}, main
    assert device == {"nx_device/15.0/shell/MuMuNxDevice.exe"}, device
    assert not (main & device)


def test_resolving_the_shipped_profiles_terminates():
    profiles = patcher.load_profiles()
    for name in profiles:
        order = patcher.resolve_requirements(profiles, [name])
        assert order[-1] == name or name in order
        assert len(order) == len(set(order)), "resolver emitted a duplicate"


# --------------------------------------------------------------------------- #
# build identity
# --------------------------------------------------------------------------- #
def test_build_short_form_applies_to_every_file_in_the_profile(tmp_path):
    _write(tmp_path, "p", _minimal("p", build='build = "deadbeefdeadbeef"'))
    profiles = patcher.load_profiles(tmp_path)
    assert profiles["p"].build == {"a.exe": "deadbeefdeadbeef"}


def test_build_table_form_is_per_file(tmp_path):
    body = _minimal("p", file="one.exe").replace("[profile]", "[profile]") + "\n"
    # Two patches in one profile, targeting different files.
    body = body.replace(
        'expect = "48 8B 05 DE AD BE EF"',
        'expect = "48 8B 05 DE AD BE EF"\n\n[[patch]]\n'
        'id = "p2"\ndescription = "p2"\nfile = "two.exe"\n'
        'signature = "48 8B 05 ?? ?? ?? ??"\n'
        'replace = "48 8B 05 11 22 33 44"\n'
        'expect = "48 8B 05 DE AD BE EF"',
    )
    body = body.replace(
        'description = "d"',
        'description = "d"\n[profile.build]\n"one.exe" = "aaaa"\n"two.exe" = "bbbb"',
    )
    _write(tmp_path, "p", body)
    profiles = patcher.load_profiles(tmp_path)
    assert profiles["p"].build == {"one.exe": "aaaa", "two.exe": "bbbb"}


def test_no_build_field_is_an_empty_map(tmp_path):
    _write(tmp_path, "p", _minimal("p"))
    assert patcher.load_profiles(tmp_path)["p"].build == {}


def test_bad_build_type_is_rejected(tmp_path):
    _write(tmp_path, "p", _minimal("p", build="build = 12345"))
    with pytest.raises(patcher.PatchError, match="string or a table"):
        patcher.load_profiles(tmp_path)


def test_shipped_profiles_record_a_build_for_every_target_file():
    """The whole point of the field is that a mismatch is diagnosable, which it
    is not if the profiles never record one."""
    for name, prof in patcher.load_profiles().items():
        for f in prof.files:
            assert f in prof.build, f"{name}: no build fingerprint for {f}"
