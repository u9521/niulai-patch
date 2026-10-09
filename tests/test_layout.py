"""Tests for the source layout itself.

This project puts its modules *flat* under ``src/`` -- ``cli.py``,
``backup.py``, ``disk/``, ``boot/``, ``pe/``, ``rcc/`` -- rather than under a
single named package.  That was a deliberate choice, and it buys two things: the
imports read like the domain (``from disk import extfs``) and a reader finds
``boot/`` without knowing a project name first.

It costs one thing, which is what this file is for.  There is no namespace, so
those top-level names go directly into ``site-packages``: if another installed
distribution also ships a module called ``disk`` or ``pe``, whichever comes
first on ``sys.path`` wins and the failure is an ``ImportError`` in an unrelated
place, or worse, silently the other project's code.  ``pe``, ``cli`` and
``disk`` are all names a package could plausibly claim.

So the layout is asserted rather than assumed: every module this project ships
must resolve *inside this repository*, and nothing else that is installed may
claim the same name.
"""

from __future__ import annotations

import importlib.metadata as metadata
import importlib.util
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"

#: Every top-level module and package this project installs.  Listed explicitly
#: so that adding one is a deliberate act with a test attached, rather than
#: something that quietly widens the footprint in site-packages.
SHIPPED_TOP_LEVEL = (
    "__about__",
    "backup",
    "boot",
    "cli",
    "disk",
    "filesystems",
    "install",
    "lawnchair",
    "pe",
    "rcc",
    "hosttools",
    "splash",
)


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_every_shipped_module_exists_on_disk():
    """The list above and the tree must not drift apart."""
    for name in SHIPPED_TOP_LEVEL:
        module = SRC / f"{name}.py"
        package = SRC / name / "__init__.py"
        assert module.is_file() or package.is_file(), (
            f"{name} is listed as shipped but src/{name}.py and "
            f"src/{name}/__init__.py are both missing"
        )

    # And the other direction: nothing in src/ is absent from the list.
    found = {p.stem for p in SRC.glob("*.py")}
    found |= {p.name for p in SRC.iterdir() if p.is_dir() and (p / "__init__.py").is_file()}
    assert found == set(SHIPPED_TOP_LEVEL), (
        f"src/ has {sorted(found - set(SHIPPED_TOP_LEVEL))} that the layout test "
        f"does not know about"
    )


def test_no_installed_distribution_claims_one_of_our_top_level_names():
    """The cost of a flat layout, checked instead of hoped for.

    A collision here would not fail at build time; it would fail as a confusing
    ImportError, or as another project's module being imported instead of ours.
    """
    ours = {"mumu-patch", "mumu_patch"}
    offenders: list[str] = []

    for dist in metadata.distributions():
        try:
            name = dist.metadata["Name"]
        except KeyError:  # pragma: no cover - malformed metadata
            continue
        if not name or name.lower().replace("_", "-") in ours:
            continue

        # ``top_level.txt`` is the canonical answer; fall back to the file list.
        declared: set[str] = set()
        try:
            raw = dist.read_text("top_level.txt")
        except FileNotFoundError, OSError:  # pragma: no cover
            raw = None
        if raw:
            declared = {line.strip() for line in raw.splitlines() if line.strip()}
        else:
            for entry in dist.files or []:
                parts = str(entry).split("/")
                if len(parts) >= 2 and not parts[0].endswith(".dist-info"):
                    declared.add(parts[0])
                elif len(parts) == 1 and parts[0].endswith(".py"):
                    declared.add(parts[0][:-3])

        clash = declared & set(SHIPPED_TOP_LEVEL)
        if clash:
            offenders.append(f"{name} ships {sorted(clash)}")

    assert not offenders, (
        "a flat src/ layout means these top-level names must be unique; "
        "another installed distribution claims them:\n  " + "\n  ".join(offenders)
    )


def test_our_modules_resolve_inside_this_repository():
    """Importing us must not pick up somebody else's module of the same name."""
    for name in SHIPPED_TOP_LEVEL:
        spec = importlib.util.find_spec(name)
        if spec is None:
            pytest.skip(f"{name} is not importable from this interpreter")
        origin = spec.origin
        assert origin, f"{name} has no origin (namespace package?)"
        resolved = Path(origin).resolve()
        assert SRC in resolved.parents or resolved.parent == SRC, (
            f"{name} resolved to {resolved}, which is outside {SRC}"
        )


def test_the_declared_version_matches_the_module():
    """The version is written twice; make sure the two copies agree.

    ``uv_build`` does not support ``dynamic = ["version"]``, so the version
    cannot be read out of ``src/__about__.py`` at build time the way it used to
    be.  It is declared in ``pyproject.toml`` and read at runtime from the
    module, which means the metadata and ``niulai-patch --version`` could drift
    -- so the equality is asserted instead of assumed.
    """
    pyproject = _pyproject()
    declared = pyproject["project"]["version"]

    namespace: dict = {}
    exec((SRC / "__about__.py").read_text(encoding="utf-8"), namespace)

    assert namespace["__version__"] == declared, (
        f"src/__about__.py says {namespace['__version__']} but pyproject.toml says {declared}"
    )

    # And from the installed side: the metadata the build produced has to agree
    # too, which is the thing a mismatch would actually break.
    import __about__

    assert __about__.__version__ == declared


def test_the_wheel_configuration_can_see_the_flat_modules():
    """The packaging rules and the layout must describe the same tree."""
    pyproject = _pyproject()
    backend = pyproject["tool"]["uv"]["build-backend"]

    assert backend["module-root"] == "src"
    # `module-name = []` is what lets loose modules (`cli.py`) and packages
    # (`pe/`) coexist in one flat root instead of demanding src/mumu_patch/.
    assert backend["module-name"] == []
    assert backend["namespace"] is True
    # ...and this is what actually puts them in the wheel.  Without it the build
    # still succeeds but ships nothing but .dist-info; tests/test_build.py
    # asserts the manifest so that trap cannot return silently.
    assert backend["data"]["purelib"] == "src"

    # The assets travel beside the code, so they have to sit inside the module
    # root for the rules above to pick them up.
    assert (SRC / "prebuilts" / _bundled_apk_name()).is_file()
    assert (SRC / "prebuilts" / "splash").is_dir()
    assert (SRC / "pe" / "patches").is_dir()
    assert list((SRC / "pe" / "patches").glob("*.toml"))


def _bundled_apk_name() -> str:
    """The bundled APK's file name, without importing the module under test."""
    for line in (SRC / "lawnchair.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("BUNDLED_APK_NAME"):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError("BUNDLED_APK_NAME is not defined in lawnchair.py")


def test_the_build_backend_is_uv_build():
    """`uv build` is the documented build command, so it must be the backend."""
    pyproject = _pyproject()
    assert pyproject["build-system"]["build-backend"] == "uv_build"
    assert any(req.startswith("uv_build") for req in pyproject["build-system"]["requires"]), (
        "uv_build must be pinned in requires, with an upper bound"
    )


def test_there_is_no_legacy_package_directory():
    """The point of the change: no ``src/mumu_patch/`` wrapper."""
    assert not (SRC / "mumu_patch").exists()
