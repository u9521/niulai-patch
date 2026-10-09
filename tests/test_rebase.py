"""Tests for `rebase`: re-resolving profiles against a different build.

The two properties that matter most, and are easiest to get wrong:

* ``--write`` must preserve every comment in the TOML files.  These profiles are
  mostly commentary, and a ``tomllib`` round-trip would throw it all away.
* A patch that cannot be placed must be reported as such, never guessed at.
"""

from __future__ import annotations

import pytest

from pe import patcher, rebase
from test_locate import _lea_to, _nops, _pe


def _patch(**kw) -> patcher.Patch:
    base = dict(
        id="t",
        description="",
        file="a.exe",
        signature="48 8B 05 ?? ?? ?? ??",
        replace="48 8B 05 11 22 33 44",
        expect="48 8B 05 DE AD BE EF",
        known_rvas=[0x1000 + 16],
    )
    base.update(kw)
    return patcher.Patch(**base)


# --------------------------------------------------------------------------- #
# rebase_patch
# --------------------------------------------------------------------------- #
def test_a_unique_signature_is_found():
    data = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF") + _nops(16), b"\0")
    out = rebase.rebase_patch(data, _patch())
    assert out.status == "unchanged"
    assert out.new_rva == 0x1000 + 16


def test_a_moved_signature_is_reported_as_found():
    data = _pe(_nops(0x30) + bytes.fromhex("488B05DEADBEEF") + _nops(16), b"\0")
    out = rebase.rebase_patch(data, _patch(known_rvas=[0x1000]))
    assert out.status == "found"
    assert out.old_rva == 0x1000
    assert out.new_rva == 0x1000 + 0x30


def test_an_absent_signature_needs_manual_work():
    data = _pe(_nops(64), b"\0")
    out = rebase.rebase_patch(data, _patch())
    assert out.status == "needs-manual"
    assert out.new_rva is None
    assert "not present" in out.detail


def test_an_ambiguous_signature_is_never_guessed():
    """Two identical sites and no anchor: the honest answer is "ambiguous"."""
    body = bytes.fromhex("488B05DEADBEEF")
    data = _pe(_nops(16) + body + _nops(16) + body + _nops(16), b"\0")
    out = rebase.rebase_patch(data, _patch())
    assert out.status == "ambiguous"
    assert out.new_rva is None
    # 16 NOPs, then the body; 16 more NOPs, then the second body.
    assert "0x1010" in out.detail and hex(0x1000 + 16 + len(body) + 16) in out.detail


def test_an_anchor_resolves_an_ambiguous_signature():
    body = bytes.fromhex("488B05DEADBEEF")
    data = _pe(b"\x11" * 4 + body + _nops(16) + b"\x22" * 4 + body + _nops(16), b"\0")
    p = _patch(anchor="22 22 22 22", known_rvas=[0x1000])
    out = rebase.rebase_patch(data, p)
    assert out.status == "found"
    # The second body, after the 0x22 anchor.
    assert out.new_rva > 0x1000 + 16


def test_a_still_valid_locator_reports_unchanged():
    from pe import locate

    rdata_rva = 0x20000
    text = _nops(16) + _lea_to(rdata_rva, 0x1000 + 16) + _nops(16)
    data = _pe(text, b"mainFaqMenuItem\0", rdata_rva=rdata_rva)
    # The signature must match the instruction the locator anchors on, or the
    # window scan finds nothing and the locator legitimately fails.
    p = _patch(
        signature="48 8D 15 ?? ?? ?? ??",
        expect="48 8D 15 00 00 00 00",
        replace="48 8D 15 11 22 33 44",
        locate=locate.Locator(kind="string-ref", value="mainFaqMenuItem", window=0x40),
        known_rvas=[0x1000 + 16],
    )
    out = rebase.rebase_patch(data, p)
    assert out.status == "unchanged"
    assert out.new_rva == 0x1000 + 16


# --------------------------------------------------------------------------- #
# report plumbing
# --------------------------------------------------------------------------- #
def test_rebase_ignores_patches_for_other_files():
    data = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF"), b"\0")
    profiles = {
        "p": patcher.Profile("p", "", [_patch(file="other.exe")]),
    }
    report = rebase.rebase(data, "a.exe", profiles)
    assert report.outcomes == []


def test_rebase_collects_outcomes_for_the_named_file():
    data = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF"), b"\0")
    profiles = {"p": patcher.Profile("p", "", [_patch()])}
    report = rebase.rebase(data, "a.exe", profiles)
    assert [o.patch_id for o in report.outcomes] == ["t"]
    assert report.outcomes[0].profile == "p"


def test_placed_and_unplaced_partition_the_outcomes():
    data = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF"), b"\0")
    profiles = {
        "p": patcher.Profile(
            "p",
            "",
            [
                _patch(),
                # A signature that is genuinely absent, so this one cannot be
                # placed.  (A *present* signature is "found" even if its recorded
                # RVA is stale -- that is the point of the search.)
                _patch(id="gone", signature="CC CC CC CC CC CC CC CC"),
            ],
        )
    }
    report = rebase.rebase(data, "a.exe", profiles)
    assert len(report.placed) == 1
    assert len(report.unplaced) == 1
    assert report.placed[0].patch_id == "t"
    assert report.unplaced[0].patch_id == "gone"


# --------------------------------------------------------------------------- #
# TOML rewriting preserves comments
# --------------------------------------------------------------------------- #
TOML_SAMPLE = """\
# A comment that must survive.
[profile]
name = "demo"
description = "d"
requires = []
build = "deadbeefdeadbeef"

# Another comment, above the patch.
[[patch]]
id = "one"
description = "first"
file = "a.exe"
# A comment inside the patch block.
locate_rva = "0x1000"
signature = "48 8B 05 ?? ?? ?? ??"
expect = "48 8B 05 DE AD BE EF"
replace = "48 8B 05 11 22 33 44"
known_rvas = ["0x1000"]

# A trailing comment.
[[patch]]
id = "two"
description = "second"
file = "a.exe"
locate_rva = "0x2000"
signature = "48 8B 05 ?? ?? ?? ??"
expect = "48 8B 05 DE AD BE EF"
replace = "48 8B 05 11 22 33 44"
known_rvas = ["0x2000"]
"""


def _sample_profile(tmp_path, monkeypatch, text=TOML_SAMPLE):
    path = tmp_path / "demo.toml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(patcher, "PATCH_DIR", tmp_path)
    monkeypatch.setattr(rebase, "_toml_path_for", lambda name: tmp_path / f"{name}.toml")
    return path


def test_edits_target_the_right_block(tmp_path, monkeypatch):
    path = _sample_profile(tmp_path, monkeypatch)
    p = _patch(id="two", known_rvas=[0x2000], locate_rva=0x2000)
    edits = rebase._edits_for(p, 0x2ABC, path)
    assert len(edits) == 2
    joined = "".join(new for _, new in edits)
    assert '"0x2abc"' in joined
    # The first patch's lines must not appear among the edits.
    assert not any('"0x1000"' in old for old, _ in edits)


def test_edits_do_not_match_an_id_mentioned_in_a_comment(tmp_path, monkeypatch):
    text = TOML_SAMPLE.replace(
        "# Another comment, above the patch.",
        '# Another comment, above the patch. id = "one" is mentioned here.',
    )
    path = _sample_profile(tmp_path, monkeypatch, text)
    p = _patch(id="one", known_rvas=[0x1000], locate_rva=0x1000)
    edits = rebase._edits_for(p, 0x1ABC, path)
    joined = "".join(new for _, new in edits)
    assert '"0x1abc"' in joined
    assert not any('"0x2000"' in old for old, _ in edits), (
        'the comment mentioning id = "one" must not cause the second block to be edited'
    )


def test_apply_edits_preserves_every_comment(tmp_path, monkeypatch):
    path = _sample_profile(tmp_path, monkeypatch)
    p = _patch(id="one", known_rvas=[0x1000], locate_rva=0x1000)
    report = rebase.RebaseReport(edits={path: rebase._edits_for(p, 0x1ABC, path)})
    rebase.apply_edits(report)

    after = path.read_text(encoding="utf-8")
    for comment in (
        "# A comment that must survive.",
        "# Another comment, above the patch.",
        "# A comment inside the patch block.",
        "# A trailing comment.",
    ):
        assert comment in after, f"lost {comment!r}"
    # And the values did change.
    assert 'locate_rva = "0x1abc"' in after
    assert 'known_rvas = ["0x1abc"]' in after
    # ...while the untouched patch kept its own.
    assert 'locate_rva = "0x2000"' in after


def test_apply_edits_is_a_no_op_for_an_unchanged_patch(tmp_path, monkeypatch):
    path = _sample_profile(tmp_path, monkeypatch)
    before = path.read_text(encoding="utf-8")
    p = _patch(id="one", known_rvas=[0x1000], locate_rva=0x1000)
    rebase.apply_edits(rebase.RebaseReport(edits={path: rebase._edits_for(p, 0x1000, path)}))
    assert path.read_text(encoding="utf-8") == before


def test_apply_edits_refuses_when_the_line_is_not_unique(tmp_path, monkeypatch):
    """A file edited by hand between the report and the write must be refused."""
    text = TOML_SAMPLE.replace('locate_rva = "0x2000"', 'locate_rva = "0x1000"')
    path = _sample_profile(tmp_path, monkeypatch, text)
    p = _patch(id="one", known_rvas=[0x1000], locate_rva=0x1000)
    edits = rebase._edits_for(p, 0x1ABC, path)
    with pytest.raises(patcher.PatchError, match="appears 2 times"):
        rebase.apply_edits(rebase.RebaseReport(edits={path: edits}))


def test_apply_edits_dry_run_writes_nothing(tmp_path, monkeypatch):
    path = _sample_profile(tmp_path, monkeypatch)
    before = path.read_text(encoding="utf-8")
    p = _patch(id="one", known_rvas=[0x1000], locate_rva=0x1000)
    rebase.apply_edits(
        rebase.RebaseReport(edits={path: rebase._edits_for(p, 0x1ABC, path)}),
        dry_run=True,
    )
    assert path.read_text(encoding="utf-8") == before


def test_edits_are_empty_for_a_patch_that_is_not_in_the_file(tmp_path, monkeypatch):
    path = _sample_profile(tmp_path, monkeypatch)
    p = _patch(id="not-there", known_rvas=[0x1000], locate_rva=0x1000)
    assert rebase._edits_for(p, 0x1ABC, path) == []


# --------------------------------------------------------------------------- #
# build refresh
# --------------------------------------------------------------------------- #
def test_rebase_generates_edits_for_found_patches_not_only_moved_ones(tmp_path, monkeypatch):
    """Regression: keying edits on "moved" alone silently skipped every patch
    whose locator broke but whose signature still scanned -- which, after a real
    version update, is most of them.  Both statuses mean the recorded RVA is now
    wrong, so both must produce edits."""
    _sample_profile(tmp_path, monkeypatch)
    # The signature sits 0x30 bytes into .text, but the profile records 0x1000.
    # A plain scan therefore finds it at a *different* RVA -> status "found".
    data = _pe(_nops(0x30) + bytes.fromhex("488B05DEADBEEF") + _nops(16), b"\0")
    p = _patch(id="one", locate_rva=None, known_rvas=[0x1000])
    profiles = {"demo": patcher.Profile("demo", "", [p])}

    report = rebase.rebase(data, "a.exe", profiles)
    assert report.outcomes[0].status == "found"
    assert report.edits, "a 'found' patch must still produce edits"
    assert any('"0x1030"' in new for _, new in report.edits[tmp_path / "demo.toml"])


def test_refresh_build_rewrites_the_fingerprint(tmp_path, monkeypatch):
    path = _sample_profile(tmp_path, monkeypatch)
    prof = patcher.Profile("demo", "", [_patch()], build={"a.exe": "deadbeefdeadbeef"})
    data = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF"), b"x\0")
    edits = rebase.refresh_build(prof, data)
    assert len(edits) == 1
    rebase.apply_edits(rebase.RebaseReport(edits={path: edits}))
    from pe import buildid

    assert f'build = "{buildid.fingerprint(data)}"' in path.read_text(encoding="utf-8")


def test_refresh_build_is_empty_when_already_current(tmp_path, monkeypatch):
    path = _sample_profile(tmp_path, monkeypatch)
    data = _pe(_nops(16) + bytes.fromhex("488B05DEADBEEF"), b"x\0")
    from pe import buildid

    fp = buildid.fingerprint(data)
    path.write_text(
        TOML_SAMPLE.replace('build = "deadbeefdeadbeef"', f'build = "{fp}"'),
        encoding="utf-8",
    )
    prof = patcher.Profile("demo", "", [_patch()], build={"a.exe": fp})
    assert rebase.refresh_build(prof, data) == []
