"""The distribution actually has to contain the program.

``uv_build`` is configured with ``module-name = []`` plus a
``[tool.uv.build-backend.data] purelib`` entry, which is an unusual combination
and fails in an unusual way: the build *succeeds* and produces a wheel
containing nothing but ``.dist-info``.  A silently empty wheel is the kind of
mistake that is only discovered after publishing, so the manifest is checked
here rather than trusted.

The non-Python assets are checked in the same pass.  They are not "source" in
any language's sense -- the 17 MB launcher APK and the two startup JPEGs -- but
``lawnchair`` and ``splash`` verify them by SHA-256 at runtime, so a wheel that
omits them installs a command that cannot work.  They have to travel with the
code and there is no importer that would notice if they stopped.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"

pytestmark = pytest.mark.slow

#: `uv build` shells out to the build backend, which on a cold cache downloads
#: it.  Generous enough for that, short enough to fail rather than hang.
_BUILD_TIMEOUT = 900


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not on PATH, so the distribution cannot be built here")
    return uv


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> tuple[Path, Path]:
    """Build a wheel and an sdist once, for every test in this module."""
    out = tmp_path_factory.mktemp("dist")
    proc = subprocess.run(
        [_uv(), "build", "--out-dir", str(out), str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=_BUILD_TIMEOUT,
    )
    if proc.returncode != 0:  # pragma: no cover - a build failure is the failure
        pytest.fail(f"`uv build` failed:\n{proc.stdout}\n{proc.stderr}")

    wheels = list(out.glob("*.whl"))
    sdists = list(out.glob("*.tar.gz"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"
    assert len(sdists) == 1, f"expected one sdist, got {sdists}"
    return wheels[0], sdists[0]


def _expected_modules() -> set[str]:
    """Every Python module under src/, as wheel-relative paths."""
    return {str(p.relative_to(SRC)) for p in SRC.rglob("*.py") if "__pycache__" not in p.parts}


def test_the_wheel_contains_every_module(built):
    """The empty-wheel failure mode, caught directly."""
    wheel, _ = built
    names = zipfile.ZipFile(wheel).namelist()

    # The layout puts the modules in .data/purelib/ rather than at the archive
    # root, so match on suffix: what matters is that each module is in there.
    for rel in _expected_modules():
        assert any(name.endswith(f"/{rel}") for name in names), (
            f"{rel} is missing from the wheel -- the flat-layout configuration "
            f"in pyproject.toml has stopped working"
        )


def test_the_wheel_contains_the_non_python_assets(built):
    """The APK and the startup artwork are load-bearing, not documentation."""
    wheel, _ = built
    names = zipfile.ZipFile(wheel).namelist()

    apk = [n for n in names if n.endswith(".apk")]
    assert len(apk) == 1, f"expected exactly the bundled launcher APK, got {apk}"

    jpegs = [n for n in names if n.endswith(".jpg")]
    assert len(jpegs) >= 2, f"the two startup images should ship too, got {jpegs}"

    profiles = [n for n in names if n.endswith(".toml") and "patches/" in n]
    on_disk = list((SRC / "pe" / "patches").glob("*.toml"))
    assert len(profiles) == len(on_disk), (
        f"{len(on_disk)} patch profiles on disk but {len(profiles)} in the wheel"
    )


def test_the_wheel_declares_the_console_script(built):
    """The installed command is the interface; a rename must reach the wheel."""
    wheel, _ = built
    entry_points = [n for n in zipfile.ZipFile(wheel).namelist() if n.endswith("entry_points.txt")]
    assert entry_points, "the wheel has no entry_points.txt"
    text = zipfile.ZipFile(wheel).read(entry_points[0]).decode("utf-8")
    assert "niulai-patch" in text, f"console script missing from {entry_points[0]}"
    assert "cli:main" in text


def test_the_sdist_carries_the_sources_and_assets(built):
    """A source distribution that cannot rebuild the wheel is not one."""
    _, sdist = built
    with tarfile.open(sdist) as archive:
        names = archive.getnames()
    for rel in _expected_modules():
        assert any(n.endswith(f"src/{rel}") for n in names), f"{rel} missing from sdist"
    assert any(n.endswith(".apk") for n in names), "the bundled APK is missing"
    assert any(n.endswith("pyproject.toml") for n in names)


def test_the_installed_wheel_can_import_and_find_its_assets(built, tmp_path):
    """End to end: unpack, import, and resolve what the modules look for.

    Importing from the unpacked wheel rather than the checkout is what makes
    this a real check -- it exercises the same ``__file__``-relative asset
    lookups an installed command would use.
    """
    wheel, _ = built
    target = tmp_path / "site"
    target.mkdir()
    with zipfile.ZipFile(wheel) as zf:
        zf.extractall(target)

    # The purelib payload has to be moved where the interpreter would see it,
    # which mirrors what a real install does with `.data/purelib/`.
    data_dirs = list(target.glob("*.data/purelib"))
    assert len(data_dirs) == 1, f"expected one purelib payload, got {data_dirs}"
    for item in data_dirs[0].iterdir():
        shutil.move(str(item), str(target / item.name))

    # `pefile` and `click` are real dependencies, so borrow them from the venv
    # running the suite instead of installing again.
    import site

    path = [str(target), *site.getsitepackages(), str(Path(sys.prefix) / "lib")]
    code = (
        "import sys; sys.path[:0] = sys.argv[1:];"
        "import cli, pe.patcher as P, lawnchair, splash;"
        "assert lawnchair.bundled_apk_path().is_file(), lawnchair.bundled_apk_path();"
        "assert P.PATCH_DIR.is_dir();"
        "assert list(P.PATCH_DIR.glob('*.toml'));"
        "assert splash.asset_path(splash.DEFAULT_NAME).is_file();"
        "print('ok')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code, *path],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"importing the unpacked wheel failed:\n{proc.stderr}"
    assert "ok" in proc.stdout
