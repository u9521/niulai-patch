"""Tests for backup, restore and the patch engine.

The end-to-end test is the one that matters: patch a file, confirm the change,
restore, and assert the bytes are identical to the original.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

import backup
from pe import patcher, sigscan


def _pe_with_text(payload: bytes) -> bytes:
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


# --------------------------------------------------------------------------- #
# backup / restore
# --------------------------------------------------------------------------- #
def test_backup_and_restore_roundtrip(tmp_path):
    target = tmp_path / "app.bin"
    original = b"ORIGINAL CONTENT" * 50
    target.write_bytes(original)

    root = tmp_path / "backups"
    with backup.BackupSession(tmp_path, "1.0.0", ["p1"], root=root) as s:
        s.backup(target)
        mpath = s.save()

    assert mpath.is_file()
    man = backup.Manifest.from_json(mpath.read_text())
    assert man.files[0].sha256 == backup.sha256_file(target)

    target.write_bytes(b"MODIFIED")
    results = backup.restore_files(man)
    assert results[0][1] == "restored"
    assert target.read_bytes() == original


def test_restore_is_idempotent(tmp_path):
    target = tmp_path / "a.bin"
    target.write_bytes(b"hello")
    root = tmp_path / "b"
    with backup.BackupSession(tmp_path, "1", ["p"], root=root) as s:
        s.backup(target)
        mp = s.save()
    man = backup.Manifest.from_json(mp.read_text())
    assert backup.restore_files(man)[0][1] == "unchanged"


def test_failed_session_keeps_its_backup(tmp_path):
    """A run that dies must NOT delete the backup it just took.

    This is the inverse of what the code used to do, and the reason is worth
    stating: the backup exists to undo the very failure in progress.  Removing
    it on failure left a half-written file with no way back -- which is exactly
    what happened to a real disk image.
    """
    target = tmp_path / "a.bin"
    target.write_bytes(b"important original bytes")
    root = tmp_path / "b"
    with (
        pytest.raises(RuntimeError),
        backup.BackupSession(tmp_path, "1", ["p"], root=root) as s,
    ):
        s.backup(target)
        target.write_bytes(b"CLOBBERED")  # the edit damages the file
        raise RuntimeError("boom")

    sessions = [p for p in root.glob("*/*") if p.is_dir()]
    assert len(sessions) == 1, "the backup must survive the failure"

    # ...and it must be discoverable and usable for recovery.
    found = backup.load_manifests(root)
    assert len(found) == 1
    _, man = found[0]
    assert man.interrupted is True, "the manifest must record that it was interrupted"
    assert backup.verify_backup(man) == []
    assert backup.restore_files(man)[0][1] == "restored"
    assert target.read_bytes() == b"important original bytes"


def test_failed_before_any_capture_leaves_nothing(tmp_path):
    """With no file captured there is nothing to keep, so no empty session.

    An empty directory that looks like a backup is worse than no directory: it
    would appear in the restore listing offering nothing.
    """
    root = tmp_path / "b"
    with pytest.raises(RuntimeError), backup.BackupSession(tmp_path, "1", ["p"], root=root):
        raise RuntimeError("boom before backing anything up")
    assert backup.load_manifests(root) == []
    assert backup.incomplete_sessions(root) == []


def test_incomplete_session_is_not_offered_as_a_backup(tmp_path):
    """A staging directory must never be listed as restorable."""
    root = tmp_path / "b" / "1"
    staging = root / ".20260101-000000.incomplete"
    staging.mkdir(parents=True)
    (staging / "manifest.json").write_text(
        '{"created": 1, "product_version": "1", "install_dir": "/x", "patch_ids": [], "files": []}'
    )
    assert backup.load_manifests(tmp_path / "b") == []
    assert len(backup.incomplete_sessions(tmp_path / "b")) == 1


def test_verify_backup_detects_a_missing_file(tmp_path):
    target = tmp_path / "a.bin"
    target.write_bytes(b"x")
    root = tmp_path / "b"
    with backup.BackupSession(tmp_path, "1", ["p"], root=root) as s:
        s.backup(target)
        mp = s.save()
    man = backup.Manifest.from_json(mp.read_text())
    Path(man.files[0].backup_path).unlink()
    problems = backup.verify_backup(man)
    assert problems and "missing" in problems[0][1]


def test_verify_backup_detects_truncation(tmp_path):
    """A short copy is the realistic failure; catch it by size, not just hash."""
    target = tmp_path / "a.bin"
    target.write_bytes(b"x" * 4096)
    root = tmp_path / "b"
    with backup.BackupSession(tmp_path, "1", ["p"], root=root) as s:
        s.backup(target)
        mp = s.save()
    man = backup.Manifest.from_json(mp.read_text())
    stored = Path(man.files[0].backup_path)
    stored.write_bytes(stored.read_bytes()[:1000])
    problems = backup.verify_backup(man)
    assert problems and "size" in problems[0][1]


def test_restore_refuses_tampered_backup(tmp_path):
    target = tmp_path / "a.bin"
    target.write_bytes(b"original")
    root = tmp_path / "b"
    with backup.BackupSession(tmp_path, "1", ["p"], root=root) as s:
        s.backup(target)
        mp = s.save()
    man = backup.Manifest.from_json(mp.read_text())
    # Corrupt the stored copy.
    import pathlib

    pathlib.Path(man.files[0].backup_path).write_bytes(b"tampered!!")
    with pytest.raises(OSError, match="hash mismatch"):
        backup.restore_files(man)


def test_restore_reports_missing_backup(tmp_path):
    target = tmp_path / "a.bin"
    target.write_bytes(b"original")
    root = tmp_path / "b"
    with backup.BackupSession(tmp_path, "1", ["p"], root=root) as s:
        s.backup(target)
        mp = s.save()
    man = backup.Manifest.from_json(mp.read_text())
    import os

    os.unlink(man.files[0].backup_path)
    assert backup.restore_files(man)[0][1] == "missing"


def test_atomic_write_replaces_content(tmp_path):
    p = tmp_path / "out.bin"
    backup.atomic_write(p, b"first")
    backup.atomic_write(p, b"second")
    assert p.read_bytes() == b"second"
    # No stray temp files left behind.
    assert [f.name for f in tmp_path.iterdir()] == ["out.bin"]


# --------------------------------------------------------------------------- #
# patch engine
# --------------------------------------------------------------------------- #
def _patch(**kw) -> patcher.Patch:
    """A well-formed patch: the rewritten bytes are wildcarded.

    Wildcarding matters -- a signature that pins the bytes it replaces cannot
    be detected after applying.  See ``Patch.validate``.
    """
    base = dict(
        id="t",
        description="",
        file="a.exe",
        signature="48 8B 05 ?? ?? ?? ??",
        replace="48 8B 05 11 22 33 44",
        expect="48 8B 05 DE AD BE EF",
    )
    base.update(kw)
    return patcher.Patch(**base)


def test_apply_patch_changes_only_target_bytes():
    data = _pe_with_text(b"\x90" * 16 + bytes.fromhex("488B05DEADBEEF") + b"\x90" * 16)
    out, res = patcher.apply_patch_to_bytes(data, _patch())
    assert res.status == "applied"
    assert res.rva == 0x1000 + 16
    diffs = [i for i in range(len(data)) if data[i] != out[i]]
    # The displacement occupies the last 4 bytes of the 7-byte signature.
    disp_lo = res.offset + 3
    changed_payload = [i for i in diffs if disp_lo <= i < disp_lo + 4]
    assert len(changed_payload) == 4
    # Nothing outside the signature and the checksum field may move.
    assert len(diffs) <= 4 + 4
    assert out[res.offset : res.offset + 7] == bytes.fromhex("488B0511223344")


def test_apply_is_idempotent():
    data = _pe_with_text(b"\x90" * 16 + bytes.fromhex("488B05DEADBEEF"))
    p = _patch()
    once, r1 = patcher.apply_patch_to_bytes(data, p)
    twice, r2 = patcher.apply_patch_to_bytes(once, p)
    assert r1.status == "applied"
    assert r2.status == "already-applied"
    assert twice == once


def test_replace_length_must_match_signature():
    data = _pe_with_text(bytes.fromhex("488B05DEADBEEF"))
    with pytest.raises(patcher.PatchError, match="same-length"):
        patcher.apply_patch_to_bytes(data, _patch(replace="90 90"))


def test_expect_mismatch_is_refused():
    data = _pe_with_text(bytes.fromhex("488B05DEADBEEF"))
    bad = _patch(expect="48 8B 05 00 00 00 00")
    with pytest.raises(patcher.PatchError, match="but expected"):
        patcher.apply_patch_to_bytes(data, bad)


def test_expect_accepts_already_patched_bytes():
    """Re-running with `expect` set must not fail on an already-patched file."""
    data = _pe_with_text(bytes.fromhex("488B05DEADBEEF"))
    p = _patch(expect="48 8B 05 DE AD BE EF")
    once, _ = patcher.apply_patch_to_bytes(data, p)
    _, res = patcher.apply_patch_to_bytes(once, p)
    assert res.status == "already-applied"


def test_anchor_disambiguates_wildcarded_signature():
    body = bytes.fromhex("488B05AABBCCDD")
    # Two identical bodies, distinguished only by what precedes them.
    data = _pe_with_text(b"\x11" * 4 + body + b"\x90" * 8 + b"\x22" * 4 + body)
    sig = "48 8B 05 ?? ?? ?? ??"
    with pytest.raises(sigscan.SignatureError):
        sigscan.scan_unique(data, sigscan.parse_signature(sig))

    p = _patch(
        signature=sig,
        replace="48 8B 05 11 22 33 44",
        expect="48 8B 05 AA BB CC DD",
        anchor="22 22 22 22",
    )
    out, res = patcher.apply_patch_to_bytes(data, p)
    # The match must be the *second* body (after the 0x22 anchor).
    assert res.offset > 0x200 + 16
    assert out[res.offset - 4 : res.offset] == b"\x22" * 4


def test_anchor_absent_is_reported():
    data = _pe_with_text(bytes.fromhex("488B05AABBCCDD"))
    p = _patch(
        signature="48 8B 05 ?? ?? ?? ??", replace="48 8B 05 11 22 33 44", anchor="99 99 99 99"
    )
    with pytest.raises(sigscan.SignatureError, match="none was preceded by anchor"):
        patcher.apply_patch_to_bytes(data, p)


def test_verify_patch_reflects_state():
    data = _pe_with_text(bytes.fromhex("488B05DEADBEEF"))
    p = _patch()
    assert not patcher.verify_patch(data, p)
    out, _ = patcher.apply_patch_to_bytes(data, p)
    assert patcher.verify_patch(out, p)


def test_checksum_is_recomputed_after_patch():
    from pe import pe

    data = _pe_with_text(bytes.fromhex("488B05DEADBEEF"))
    out, _ = patcher.apply_patch_to_bytes(data, _patch())
    info = pe.parse(out)
    assert info.checksum == pe.pe_checksum(out, info.checksum_offset)


def test_validate_rejects_fully_literal_signature():
    """A signature pinning the bytes it rewrites would be undetectable."""
    p = patcher.Patch(
        id="bad",
        description="",
        file="a.exe",
        signature="48 8B 05 DE AD BE EF",
        replace="48 8B 05 11 22 33 44",
    )
    with pytest.raises(patcher.PatchError, match="undetectable"):
        p.validate()


def test_validate_accepts_wildcarded_signature():
    _patch().validate()  # must not raise


def test_validate_rejects_length_mismatch():
    with pytest.raises(patcher.PatchError, match="same-length"):
        _patch(replace="90 90").validate()


# --------------------------------------------------------------------------- #
# profiles
# --------------------------------------------------------------------------- #
def test_shipped_profiles_load():
    profiles = patcher.load_profiles()
    assert profiles, "expected at least one shipped profile"
    for prof in profiles.values():
        for p in prof.patches:
            # Signature and replacement must always be the same length.
            assert p.parsed_signature().length == len(p.replacement_bytes())
            assert p.file


def test_locate_is_public_and_honours_anchor():
    """Regression: the CLI once used scan_unique directly and reported an
    anchored patch as ambiguous, contradicting what `patch` would do."""
    body = bytes.fromhex("488B05AABBCCDD")
    data = _pe_with_text(b"\x11" * 4 + body + b"\x90" * 8 + b"\x22" * 4 + body)
    p = _patch(expect="48 8B 05 AA BB CC DD", anchor="22 22 22 22")
    m = patcher.locate(data, p)
    assert data[m.offset - 4 : m.offset] == b"\x22" * 4


# --------------------------------------------------------------------------- #
# RVA-anchored location
# --------------------------------------------------------------------------- #
def test_validate_rejects_partially_pinned_signature():
    """Regression: a signature may contain a wildcard and still pin bytes the
    replacement overwrites.  The original check only looked for the presence of
    a wildcard, so this slipped through and produced an undetectable patch."""
    p = patcher.Patch(
        id="bad",
        description="",
        file="a.exe",
        # wildcards at 17..20, but 15..16 are pinned and also get replaced
        signature="48 8B CE FF 15 ?? ?? ?? ?? 90 48 8D 4D 10 E8",
        replace="48 8B CE 90 90 90 90 90 90 90 48 8D 4D 10 E8",
    )
    with pytest.raises(patcher.PatchError, match="offset"):
        p.validate()


def test_validate_accepts_fully_wildcarded_mutable_bytes():
    p = patcher.Patch(
        id="ok",
        description="",
        file="a.exe",
        signature="48 8B CE ?? ?? ?? ?? ?? ?? 90 48 8D 4D 10 E8",
        replace="48 8B CE 90 90 90 90 90 90 90 48 8D 4D 10 E8",
    )
    p.validate()


def test_locate_rva_patches_exact_site():
    """Two identical bodies: a plain scan is ambiguous, an RVA is not."""
    body = bytes.fromhex("488BCE") + b"\x01\x02\x03\x04\x05\x06" + bytes.fromhex("90488D4D10E8")
    data = _pe_with_text(body + b"\x90" * 16 + body)
    from pe import pe as _pe

    info = _pe.parse(data)
    second = _pe.rva_to_offset(info, 0x1000 + len(body) + 16)
    second_rva = _pe.offset_to_rva(info, second)

    p = patcher.Patch(
        id="rva",
        description="",
        file="a.exe",
        signature="48 8B CE ?? ?? ?? ?? ?? ?? 90 48 8D 4D 10 E8",
        replace="48 8B CE 90 90 90 90 90 90 90 48 8D 4D 10 E8",
        locate_rva=hex(second_rva),
        expect="48 8B CE 01 02 03 04 05 06 90 48 8D 4D 10 E8",
    )
    out, res = patcher.apply_patch_to_bytes(data, p)
    assert res.status == "applied"
    assert res.rva == second_rva
    # the first body must be untouched
    assert out[0x200 : 0x200 + len(body)] == body


def test_locate_rva_rejects_wrong_build():
    body = bytes.fromhex("488BCE") + b"\x01\x02\x03\x04\x05\x06" + bytes.fromhex("90488D4D10E8")
    data = _pe_with_text(b"\x90" * 64 + body)
    p = patcher.Patch(
        id="rva",
        description="",
        file="a.exe",
        signature="48 8B CE ?? ?? ?? ?? ?? ?? 90 48 8D 4D 10 E8",
        replace="48 8B CE 90 90 90 90 90 90 90 48 8D 4D 10 E8",
        locate_rva="0x1000",  # wrong address: bytes there are NOPs
    )
    with pytest.raises(sigscan.SignatureError, match="different build"):
        patcher.apply_patch_to_bytes(data, p)


def test_locate_rva_roundtrip_and_idempotency():
    body = bytes.fromhex("488BCE") + b"\x01\x02\x03\x04\x05\x06" + bytes.fromhex("90488D4D10E8")
    data = _pe_with_text(b"\x90" * 8 + body)
    p = patcher.Patch(
        id="rva",
        description="",
        file="a.exe",
        signature="48 8B CE ?? ?? ?? ?? ?? ?? 90 48 8D 4D 10 E8",
        replace="48 8B CE 90 90 90 90 90 90 90 48 8D 4D 10 E8",
        locate_rva="0x1008",
        expect="48 8B CE 01 02 03 04 05 06 90 48 8D 4D 10 E8",
    )
    once, r1 = patcher.apply_patch_to_bytes(data, p)
    assert r1.status == "applied"
    assert patcher.verify_patch(once, p), "patch must be visible after applying"
    twice, r2 = patcher.apply_patch_to_bytes(once, p)
    assert r2.status == "already-applied"
    assert twice == once
