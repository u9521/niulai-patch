"""Tests for VM image discovery and the disk-editing CLI commands.

The discovery logic decides *which* file gets edited, so a bug here is as
damaging as a bug in the writer: it could aim an edit at the wrong product's
image.  The tests build a fake installation tree and check that the right image
is chosen and that ambiguity is reported.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

import cli
from disk import images


def make_install(
    root: Path,
    *,
    product: str = "MuMuPlayer-15.0-base",
    version: str = "15.0",
    with_system: bool = True,
) -> Path:
    """Create a minimal MuMu-like directory tree."""
    vm_dir = root / "nx_device" / version / "vms" / product
    vm_dir.mkdir(parents=True)
    if with_system:
        (vm_dir / "system.vdi").write_bytes(b"\x00" * 1024)
    (vm_dir / "data.vdi").write_bytes(b"\x00" * 512)
    return vm_dir


@pytest.fixture
def isolated_env(monkeypatch):
    """Point discovery at a temp tree and hide the real installation.

    ``images._install_roots`` always appends the standard Windows locations, so
    on a machine that actually has MuMu installed a test would silently pick up
    the real image.  Clearing the fallback list keeps these tests honest.
    """
    monkeypatch.setattr(images, "_install_roots", _env_only)
    return monkeypatch


def _env_only(explicit=None):
    import os

    roots = []
    if explicit:
        roots.append(Path(explicit))
    env = os.environ.get("MUMU_INSTALL_DIR")
    if env:
        roots.append(Path(env))
    return roots


# --------------------------------------------------------------------------- #
# images
# --------------------------------------------------------------------------- #
def test_finds_the_product_holding_a_system_image(tmp_path, isolated_env):
    vm_dir = make_install(tmp_path)
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    found = images.find_vm_images()
    assert found.system == vm_dir / "system.vdi"
    assert found.product == "MuMuPlayer-15.0-base"


def test_explicit_install_dir_wins(tmp_path, isolated_env):
    explicit = tmp_path / "explicit"
    other = tmp_path / "other"
    make_install(explicit, product="A-15.0")
    make_install(other, product="B-15.0")
    isolated_env.setenv("MUMU_INSTALL_DIR", str(other))
    found = images.find_vm_images(explicit)
    assert found.product == "A-15.0"


def test_directory_without_system_vdi_is_skipped(tmp_path, isolated_env):
    root = tmp_path / "inst"
    make_install(root, product="no-system", with_system=False)
    real = make_install(root, product="has-system", with_system=True)
    isolated_env.setenv("MUMU_INSTALL_DIR", str(root))
    found = images.find_vm_images()
    assert found.system == real / "system.vdi"


def test_missing_installation_reports_where_it_looked(tmp_path, isolated_env):
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path / "nothing-here"))
    with pytest.raises(images.ImageError) as exc:
        images.find_vm_images()
    assert "no system.vdi found" in str(exc.value)


def test_product_filter_that_matches_nothing_is_reported(tmp_path, isolated_env):
    make_install(tmp_path, product="MuMuPlayer-15.0-base")
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    with pytest.raises(images.ImageError) as exc:
        images.find_vm_images(product="12.0")
    assert "matching" in str(exc.value)


def test_all_vm_images_lists_every_product(tmp_path, isolated_env):
    make_install(tmp_path, product="A-15.0")
    make_install(tmp_path, product="B-15.0")
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    found = images.all_vm_images()
    assert {f.product for f in found} == {"A-15.0", "B-15.0"}


def test_vm_images_paths(tmp_path, isolated_env):
    vm_dir = make_install(tmp_path)
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    found = images.find_vm_images()
    assert found.data == vm_dir / "data.vdi"
    assert len(found.all_vdi()) == 2


# --------------------------------------------------------------------------- #
# CLI: doctor
# --------------------------------------------------------------------------- #
def test_doctor_reports_missing_tools_and_images(tmp_path, isolated_env):
    """doctor must not crash when nothing is installed."""
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path / "absent"))
    result = CliRunner().invoke(cli.main, ["doctor"])
    assert result.exit_code == 0
    assert "helper binaries" in result.output


def test_doctor_lists_images_for_a_fake_install(tmp_path, isolated_env):
    make_install(tmp_path)
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    result = CliRunner().invoke(cli.main, ["doctor"])
    assert result.exit_code == 0
    assert "system.vdi" in result.output


def test_doctor_reports_an_unparseable_image_without_crashing(tmp_path, isolated_env):
    """A broken image is a finding for doctor to report, not a crash."""
    make_install(tmp_path)  # writes 1024 zero bytes, not a real VDI
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    result = CliRunner().invoke(cli.main, ["doctor"])
    assert result.exit_code == 0
    assert "cannot parse" in result.output


# --------------------------------------------------------------------------- #
# CLI: lawnchair
# --------------------------------------------------------------------------- #
def test_lawnchair_without_a_system_image_fails_clearly(tmp_path, isolated_env):
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path / "absent"))
    result = CliRunner().invoke(cli.main, ["lawnchair", "--apk", "x.apk"])
    assert result.exit_code != 0
    assert "no system.vdi" in result.output or "not found" in result.output


def test_lawnchair_rejects_a_missing_apk_file(tmp_path, isolated_env):
    make_install(tmp_path)
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    result = CliRunner().invoke(cli.main, ["lawnchair", "--apk", str(tmp_path / "nope.apk")])
    assert result.exit_code != 0
    assert "APK not found" in result.output


def test_lawnchair_rejects_a_non_apk_file(tmp_path, isolated_env):
    """The guard must fire before anything is written."""
    make_install(tmp_path)
    isolated_env.setenv("MUMU_INSTALL_DIR", str(tmp_path))
    junk = tmp_path / "junk.apk"
    junk.write_bytes(b"this is not an apk" * 100000)
    result = CliRunner().invoke(cli.main, ["lawnchair", "--apk", str(junk)])
    assert result.exit_code != 0
    assert "not usable" in result.output or "ZIP" in result.output


# --------------------------------------------------------------------------- #
# Write-failure diagnostics
# --------------------------------------------------------------------------- #
def test_a_permission_failure_suggests_closing_the_emulator():
    """The hint the removed "is MuMu running?" guard used to give.

    It is produced from the error we actually got rather than predicted before
    the write, because the prediction was unreliable: under WSL ``tasklist`` is
    not on ``PATH``, so the old check answered "not running" no matter what.
    """
    exc = OSError(13, "Permission denied")
    exc.filename = r"C:\Program Files\Netease\MuMu\nx_main\MuMuNxMain.exe"
    text = cli._write_failure(exc)
    assert "close the emulator" in text
    assert "Administrator" in text
    assert "MuMuNxMain.exe" in text


def test_a_failure_under_the_backup_root_says_so_instead():
    """The more specific diagnosis wins.

    An EPERM against the backup directory is not the emulator holding a file,
    and sending the reader to "close MuMu" would waste their time.
    """
    import backup

    exc = OSError(13, "Permission denied")
    exc.filename = str(backup.default_backup_root() / "p" / "20260101" / "system.vdi")
    text = cli._write_failure(exc)
    assert "backup directory is not writable" in text
    assert "MUMU_PATCH_BACKUP_ROOT" in text
    assert "close the emulator" not in text


def test_an_unrecognised_failure_still_names_the_path():
    exc = OSError(28, "No space left on device")
    exc.filename = "/tmp/x"
    text = cli._write_failure(exc)
    assert "No space left on device" in text
    assert "/tmp/x" in text


def test_the_running_emulator_check_is_gone():
    """Removed on purpose: system.vdi is Readonly, so the guest never writes it.

    The config says ``type="Readonly"`` with ``nemud.system_writable=0``, which
    makes "is MuMu running?" meaningless for the disk commands -- and it was
    silently useless under WSL for the host-file commands too.
    """
    assert not hasattr(cli, "_running_mumu_processes")
