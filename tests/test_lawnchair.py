"""Tests for launcher replacement and helper-tool discovery.

The launcher feature writes into a 1.8 GB image that every emulator instance
shares, so the tests here focus on the decisions made *before* a byte is
written: is this the launcher we think it is, is the replacement a real APK for
this ABI, and does it fit.  Those are the checks that turn a mistake into an
error message instead of a device that will not boot.

The fixtures build a small APK and a small ext2 image in a temp directory, so
the suite is hermetic.  The real image is exercised separately, read-only, in
``test_disk.py``.
"""

from __future__ import annotations

import io
import zipfile

import pytest

import lawnchair


def make_apk(
    *,
    package: str = "app.lawnchair",
    abis: tuple[str, ...] = ("x86_64",),
    dex: bool = True,
    pad_to: int = 0,
) -> bytes:
    """Build a minimal but structurally valid APK."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # A binary AndroidManifest is really UTF-16-ish; the reader only looks
        # for the package string, so storing it that way is faithful enough.
        z.writestr("AndroidManifest.xml", package.encode("utf-16-le"))
        if dex:
            z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)
        for abi in abis:
            z.writestr(f"lib/{abi}/libhoko_blur.so", b"\x7fELF" + b"\x00" * 100)
    data = buf.getvalue()
    if pad_to and len(data) < pad_to:
        data += b"\x00" * (pad_to - len(data))
    return data


# --------------------------------------------------------------------------- #
# APK validation
# --------------------------------------------------------------------------- #
def test_valid_apk_passes():
    assert lawnchair.verify_apk_is_launcher(make_apk()) == []


def test_non_zip_is_rejected():
    problems = lawnchair.verify_apk_is_launcher(b"not a zip at all")
    assert problems and "not a ZIP" in problems[0]


def test_apk_without_manifest_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", b"x")
    problems = lawnchair.verify_apk_is_launcher(buf.getvalue())
    assert any("AndroidManifest" in p for p in problems)


def test_apk_without_dex_is_rejected():
    problems = lawnchair.verify_apk_is_launcher(make_apk(dex=False))
    assert any("classes" in p for p in problems)


def test_apk_without_x86_64_is_rejected():
    """The guest reports ro.product.abi=x86_64, so an arm-only APK cannot run."""
    problems = lawnchair.verify_apk_is_launcher(make_apk(abis=("arm64-v8a",)))
    assert any("x86_64" in p for p in problems)


def test_apk_with_extra_abis_including_x86_64_is_accepted():
    apk = make_apk(abis=("arm64-v8a", "armeabi-v7a", "x86", "x86_64"))
    assert lawnchair.verify_apk_is_launcher(apk) == []


def test_apk_for_a_different_package_is_rejected():
    problems = lawnchair.verify_apk_is_launcher(make_apk(package="com.other.launcher"))
    assert any("app.lawnchair" in p for p in problems)


def test_corrupt_zip_is_reported():
    good = make_apk()
    broken = good[:100] + b"\xff" * 50
    problems = lawnchair.verify_apk_is_launcher(broken)
    assert problems


# --------------------------------------------------------------------------- #
# Replacement guards
# --------------------------------------------------------------------------- #
class _FakeFs:
    """Enough of extfs.Ext2 for the size/free-space checks in replace_launcher."""

    def __init__(self, free_blocks: int = 0, block_size: int = 4096):
        self.free_blocks = free_blocks
        self.block_size = block_size


class FakeSystemImage(lawnchair.SystemImage):
    """A SystemImage whose filesystem is replaced by an in-memory double."""

    def __init__(self, installed: bytes, *, free_blocks: int = 0, block_size: int = 4096):
        self._installed = bytearray(installed)
        self.writes = 0
        self.fs = _FakeFs(free_blocks, block_size)

    def check_launcher(self):
        import hashlib

        data = bytes(self._installed)
        digest = hashlib.sha256(data).hexdigest()
        return lawnchair.ApkCheck(
            path=lawnchair.LAUNCHER_APK,
            size=len(data),
            sha256=digest,
            is_replacement=digest == lawnchair.BUNDLED_APK_SHA256,
            is_fork=digest == lawnchair.FORK_SHA256,
        )

    def replace_launcher(self, apk, *, expect_fork=True):
        return lawnchair.SystemImage.replace_launcher(self, apk, expect_fork=expect_fork)

    def _fake_fs_replace(self, path, apk):  # pragma: no cover - replaced below
        raise AssertionError


@pytest.fixture
def patch_fs_write(monkeypatch):
    """Make the in-memory double accept writes into its bytearray."""

    def fake_replace_file_in_place(self, path, data, **kwargs):
        assert path == lawnchair.LAUNCHER_APK
        self._installed = bytearray(data)

    monkeypatch.setattr(lawnchair.extfs.Ext2, "replace_file_in_place", fake_replace_file_in_place)


def test_oversized_replacement_is_refused(monkeypatch, patch_fs_write):
    """A 43 MB APK with no free space must be refused, not attempted.

    The writer can allocate, but only from space the filesystem actually
    reports.  With zero free blocks the guard has to fire before anything is
    written.
    """
    img = FakeSystemImage(b"PK\x03\x04" + b"\x00" * 100, free_blocks=0)
    monkeypatch.setattr(
        type(img),
        "check_launcher",
        lambda self: lawnchair.ApkCheck(
            path=lawnchair.LAUNCHER_APK,
            size=20_000_000,
            sha256="x" * 64,
            is_replacement=False,
            is_fork=True,
        ),
    )
    big = make_apk(pad_to=43_000_000)
    with pytest.raises(lawnchair.LawnchairError) as exc:
        img.replace_launcher(big)
    assert "free" in str(exc.value).lower()


def test_unrecognised_installed_apk_is_refused(monkeypatch):
    """A different MuMu build must be reported, not silently overwritten."""
    img = FakeSystemImage(b"PK\x03\x04" + b"\x00" * 100)
    monkeypatch.setattr(
        type(img),
        "check_launcher",
        lambda self: lawnchair.ApkCheck(
            path=lawnchair.LAUNCHER_APK,
            size=43_330_672,
            sha256="f" * 64,
            is_replacement=False,
            is_fork=False,
        ),
    )
    with pytest.raises(lawnchair.LawnchairError) as exc:
        img.replace_launcher(make_apk())
    message = str(exc.value)
    assert "unrecognised build" in message or "not the known" in message
    # The message must name the way out, because a test-signed build is
    # unrecognised by definition and this refusal is otherwise a dead end.
    assert "--allow-unknown-installed" in message


def test_an_unrecognised_installed_apk_can_be_overwritten_on_request(monkeypatch, patch_fs_write):
    """The override exists for test-signed builds this tool did not write.

    Re-signing a build changes its digest, so a launcher installed with
    ``adb install`` is never one of the two pinned hashes.  Without an explicit
    way through, the tool could not be used again on its own output.
    """
    img = FakeSystemImage(b"PK\x03\x04" + b"\x00" * 100)
    replacement = make_apk(pad_to=1_200_000)
    installed = {"data": None}

    class AcceptingFs(_FakeFs):
        """Records the write instead of touching a filesystem."""

        def replace_file_in_place(self, path, data, **kwargs):
            assert path == lawnchair.LAUNCHER_APK
            installed["data"] = data

    img.fs = AcceptingFs()
    # The installed build is unrecognised both before and after the write, so
    # the same stub serves the pre-check and the post-write verification.
    monkeypatch.setattr(
        type(img),
        "check_launcher",
        lambda self: lawnchair.ApkCheck(
            path=lawnchair.LAUNCHER_APK,
            size=43_330_672,
            sha256="f" * 64,
            is_replacement=False,
            is_fork=False,
        ),
    )
    # Verification compares size and digest, so make the check report the
    # replacement that was just "written".
    import hashlib

    monkeypatch.setattr(
        type(img),
        "check_launcher",
        lambda self: lawnchair.ApkCheck(
            path=lawnchair.LAUNCHER_APK,
            size=len(installed["data"]) if installed["data"] else 43_330_672,
            sha256=(
                hashlib.sha256(installed["data"]).hexdigest() if installed["data"] else "f" * 64
            ),
            is_replacement=False,
            is_fork=False,
        ),
    )
    after = img.replace_launcher(replacement, expect_fork=False)
    assert installed["data"] == replacement
    assert after.size == len(replacement)


def test_non_zip_replacement_is_refused(monkeypatch, patch_fs_write):
    img = FakeSystemImage(b"PK\x03\x04" + b"\x00" * 100)
    monkeypatch.setattr(
        type(img),
        "check_launcher",
        lambda self: lawnchair.ApkCheck(
            path=lawnchair.LAUNCHER_APK,
            size=50_000_000,
            sha256="x" * 64,
            is_replacement=False,
            is_fork=True,
        ),
    )
    with pytest.raises(lawnchair.LawnchairError) as exc:
        img.replace_launcher(b"definitely not a zip")
    assert "ZIP signature" in str(exc.value)


def test_implausibly_small_replacement_is_refused(monkeypatch, patch_fs_write):
    img = FakeSystemImage(b"PK\x03\x04" + b"\x00" * 100)
    monkeypatch.setattr(
        type(img),
        "check_launcher",
        lambda self: lawnchair.ApkCheck(
            path=lawnchair.LAUNCHER_APK,
            size=50_000_000,
            sha256="x" * 64,
            is_replacement=False,
            is_fork=True,
        ),
    )
    with pytest.raises(lawnchair.LawnchairError) as exc:
        img.replace_launcher(b"PK\x03\x04" + b"\x00" * 100)
    assert "far too small" in str(exc.value)


# --------------------------------------------------------------------------- #
# Constants that the rest of the tool depends on
# --------------------------------------------------------------------------- #
def test_known_hashes_are_recorded():
    assert len(lawnchair.FORK_SHA256) == 64
    assert len(lawnchair.BUNDLED_APK_SHA256) == 64
    # The replacement has to be smaller than what it replaces, or writing it
    # into an existing pickled image would need to grow the partition.
    assert lawnchair.FORK_SIZE > lawnchair.BUNDLED_APK_SIZE


def test_bundled_apk_is_where_the_module_says_it_is():
    assert lawnchair.BUNDLED_APK.name == lawnchair.BUNDLED_APK_NAME
    assert lawnchair.BUNDLED_APK.parent.name == "prebuilts"


def test_bundled_apk_resolver_prefers_a_location_that_exists(tmp_path, monkeypatch):
    """Both the checkout and installed-package layouts have to be findable."""
    missing = tmp_path / "nope" / "x.apk"
    present = tmp_path / "here" / "x.apk"
    present.parent.mkdir(parents=True)
    present.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(lawnchair, "_BUNDLED_APK_CANDIDATES", (missing, present))
    assert lawnchair.bundled_apk_path() == present


def test_bundled_apk_resolver_falls_back_to_a_named_path(tmp_path, monkeypatch):
    """With nothing on disk it must still return a path worth reporting."""
    missing = tmp_path / "nope" / "x.apk"
    monkeypatch.setattr(lawnchair, "_BUNDLED_APK_CANDIDATES", (missing,))
    assert lawnchair.bundled_apk_path() == missing


def test_bundled_apk_matches_its_recorded_identity():
    """The checked-in build must be the one the tool claims to install.

    Skips rather than fails when ``prebuilts/`` is absent, so a source-only
    checkout can still run the suite -- the hash is what matters, and it is
    verified here against the real file whenever there is one.
    """
    import hashlib

    path = lawnchair.bundled_apk_path()
    if not path.is_file():
        pytest.skip("the bundled APK is not present in this checkout")
    data = path.read_bytes()
    assert len(data) == lawnchair.BUNDLED_APK_SIZE
    assert hashlib.sha256(data).hexdigest() == lawnchair.BUNDLED_APK_SHA256
    assert lawnchair.verify_apk_is_launcher(data) == []


def test_stale_oat_names_cover_both_artefacts():
    assert "Lawnchair.odex" in lawnchair.STALE_OAT_FILES
    assert "Lawnchair.vdex" in lawnchair.STALE_OAT_FILES


# --------------------------------------------------------------------------- #
# Tool discovery
# --------------------------------------------------------------------------- #
def test_missing_tool_names_where_it_looked(monkeypatch):
    import hosttools

    monkeypatch.setattr(hosttools, "_search_dirs", lambda: [])
    monkeypatch.setattr(hosttools.shutil, "which", lambda name: None)
    with pytest.raises(hosttools.ToolError) as exc:
        hosttools.find_tool("vbox-img")
    assert "could not find" in str(exc.value)


def test_optional_tool_returns_none(monkeypatch):
    import hosttools

    monkeypatch.setattr(hosttools, "_search_dirs", lambda: [])
    monkeypatch.setattr(hosttools.shutil, "which", lambda name: None)
    assert hosttools.find_tool("no-such-tool", required=False) is None


def test_tool_found_in_an_explicit_directory(tmp_path, monkeypatch):
    import hosttools

    exe = tmp_path / "vbox-img.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 100)
    monkeypatch.setattr(hosttools, "_search_dirs", lambda: [tmp_path])
    found = hosttools.find_tool("vbox-img")
    assert found is not None
    assert found.path == exe


def test_env_var_adds_a_search_directory(tmp_path, monkeypatch):
    import hosttools

    exe = tmp_path / "vbox-img.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("MUMU_PATCH_TOOL_DIR", str(tmp_path))
    monkeypatch.setattr(hosttools, "_hypervisor_dirs", lambda: [])
    monkeypatch.setattr(hosttools.shutil, "which", lambda name: None)
    found = hosttools.find_tool("vbox-img")
    assert found is not None and found.path == exe
