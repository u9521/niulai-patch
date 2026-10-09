"""The bundled startup artwork and the `splash --bundled` path.

The assets are real files under ``prebuilts/splash/`` and are written straight
into a 14 MB resource container, so these tests check the properties that make
that safe: the format, the aspect, the byte budget, and the recorded digests.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import splash as splash_assets

pytest.importorskip("PIL")
from PIL import Image


# --------------------------------------------------------------------------- #
# the shipped files
# --------------------------------------------------------------------------- #
def test_both_bundled_images_exist():
    for name in (splash_assets.LANDSCAPE_NAME, splash_assets.PORTRAIT_NAME):
        path = splash_assets.asset_path(name)
        assert path.is_file(), f"missing bundled splash: {path}"


def test_default_is_the_landscape_file():
    """Every one of the nine resource slots is 16:9, so 16:9 is the default.

    The slots are named `img_startup_vertical*` and `img_startup_landscape*`,
    but all nine are 16:9 in the container -- the vendor ships the same shape
    for both.  Picking landscape by default therefore matches what the
    application already expects.
    """
    assert splash_assets.DEFAULT_NAME == splash_assets.LANDSCAPE_NAME


def test_bundled_images_fit_the_smallest_slot():
    """A file over the smallest slot's budget cannot be applied to all nine."""
    for name in (splash_assets.LANDSCAPE_NAME, splash_assets.PORTRAIT_NAME):
        data = splash_assets.load(name)
        assert len(data) <= splash_assets.SLOT_BUDGET, (
            f"{name} is {len(data):,} bytes, over the {splash_assets.SLOT_BUDGET:,} byte budget"
        )


def test_bundled_images_are_jpegs_with_the_expected_aspect():
    expected = {
        splash_assets.LANDSCAPE_NAME: (3200, 1800),
        splash_assets.PORTRAIT_NAME: (1800, 3200),
    }
    for name, size in expected.items():
        import io

        im = Image.open(io.BytesIO(splash_assets.load(name)))
        assert im.format == "JPEG", name
        assert im.size == size, f"{name}: {im.size} != {size}"
        assert im.mode == "RGB", name


def test_landscape_asset_is_sixteen_by_nine():
    """The landscape crop must not have stretched the picture."""
    import io

    im = Image.open(io.BytesIO(splash_assets.load(splash_assets.LANDSCAPE_NAME)))
    w, h = im.size
    assert abs(w / h - 16 / 9) < 0.01


def test_portrait_asset_is_nine_by_sixteen():
    import io

    im = Image.open(io.BytesIO(splash_assets.load(splash_assets.PORTRAIT_NAME)))
    w, h = im.size
    assert abs(h / w - 16 / 9) < 0.01


def test_recorded_digests_match_the_files():
    """`load` verifies these, so a mismatch means the check is not wired up.

    The digests are what catches a truncated or hand-edited asset before it is
    written into the container, where the only symptom would be a half-drawn
    splash.
    """
    for name, recorded in (
        (splash_assets.LANDSCAPE_NAME, splash_assets.LANDSCAPE_SHA256),
        (splash_assets.PORTRAIT_NAME, splash_assets.PORTRAIT_SHA256),
    ):
        assert recorded != "PENDING", f"{name} has no recorded digest"
        got = hashlib.sha256(splash_assets.asset_path(name).read_bytes()).hexdigest()
        assert got == recorded, f"{name}: recorded {recorded}, file is {got}"


def test_load_rejects_a_corrupted_asset(tmp_path, monkeypatch):
    """A byte flip must be caught rather than written into the container."""
    good = splash_assets.asset_path(splash_assets.LANDSCAPE_NAME)
    bad = tmp_path / splash_assets.LANDSCAPE_NAME
    data = bytearray(good.read_bytes())
    data[len(data) // 2] ^= 0xFF
    bad.write_bytes(bytes(data))

    monkeypatch.setattr(splash_assets, "_CANDIDATE_ROOTS", (tmp_path,))
    with pytest.raises(splash_assets.SplashAssetError, match="SHA-256"):
        splash_assets.load(splash_assets.LANDSCAPE_NAME)


def test_unknown_asset_name_is_rejected():
    with pytest.raises(splash_assets.SplashAssetError, match="unknown bundled splash"):
        splash_assets.asset_path("nope.jpg")


# --------------------------------------------------------------------------- #
# CLI: splash --bundled
# --------------------------------------------------------------------------- #
def _fake_install(root: Path) -> Path:
    """A tree with just enough for `splash` to find a resource container."""
    rcc_dir = root / "nx_device" / "15.0" / "shell" / "rcc"
    rcc_dir.mkdir(parents=True)
    # `find_install` recognises a root by this marker, not by the container.
    (root / "configs").mkdir(exist_ok=True)
    # A real container is not needed to exercise the option parsing and the
    # mutual-exclusion check; those fail before the container is parsed.
    (rcc_dir / "NxDeviceResource.rcc").write_bytes(b"\x00" * 64)
    return root


def test_splash_rejects_bundled_with_image(tmp_path, monkeypatch):
    """The two sources are exclusive, and the error is raised before any read."""
    from click.testing import CliRunner

    import cli

    root = _fake_install(tmp_path)
    monkeypatch.setenv("MUMU_INSTALL_DIR", str(root))
    result = CliRunner().invoke(cli.main, ["splash", "--bundled", "--image", "x.jpg"])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_splash_bundled_reports_a_missing_container(tmp_path, monkeypatch):
    """A bad install is reported by path, not as a traceback."""
    from click.testing import CliRunner

    import cli

    root = _fake_install(tmp_path)
    (root / "nx_device" / "15.0" / "shell" / "rcc" / "NxDeviceResource.rcc").unlink()
    monkeypatch.setenv("MUMU_INSTALL_DIR", str(root))
    result = CliRunner().invoke(cli.main, ["splash", "--bundled", "--dry-run"])
    assert result.exit_code != 0
    assert "resource container not found" in result.output
