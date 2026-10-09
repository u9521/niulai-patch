"""Locate the helper binaries the disk-editing features call.

Why this exists
---------------
Editing inside ``system.vdi`` needs one Windows executable that this project
does not implement itself:

``vbox-img.exe``
    Ships with MuMu; converts between VDI and RAW, and reports authoritative
    geometry (used to cross-check our own header parser).

Everything else is done in-process.  The partition table is edited by
``disk.partition`` and ext2/ext4 is both read and written by ``disk.extfs``,
including growing a filesystem after its partition grows.  There is deliberately
no build step, no self-compiled helper and no dependency on a non-shipped
external binary: the partition editor never shells out to ``sgdisk``/``sfdisk``,
and ``debugfs`` appears only as the cautionary example in ``disk/extfs.py``'s
docstring, never as a call.

Resolution order, most specific first:

1. an explicit path passed by the caller (``--tool-dir``);
2. ``$MUMU_PATCH_TOOL_DIR``;
3. the MuMu installation itself (``nx_device/<ver>/hypervisor/``), which is
   where ``vbox-img.exe`` comes from;
4. ``PATH``.

``vbox-img.exe`` is *theirs* and must match the emulator's own VirtualBox build,
since it is the authority on VDI layout -- so it is located, never built.

Why this module is called ``hosttools``
--------------------------------------
It is the honest description: tools that live on the host.  A flat ``src/``
layout puts every module directly into ``site-packages``, so a short generic name
is a real collision risk; ``tests/test_layout.py`` asserts that no module here
claims a top-level name an installed distribution already owns.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

#: Repository root, i.e. the directory holding ``src/`` and ``tools/``.  This
#: file lives directly in ``src/``, so the root is one level up -- it was two
#: when the package was ``src/mumu_patch/``.
REPO_ROOT = Path(__file__).resolve().parent.parent


class ToolError(Exception):
    """Raised when a required helper binary cannot be found or run."""


@dataclass(frozen=True)
class Tool:
    """A located executable."""

    name: str
    path: Path
    version: str = ""

    def exists(self) -> bool:
        return self.path.is_file()


def _install_roots() -> list[Path]:
    roots: list[Path] = []
    env = os.environ.get("MUMU_INSTALL_DIR")
    if env:
        roots.append(Path(env))
    for cand in (r"C:\Program Files\Netease\MuMu", r"C:\Program Files (x86)\Netease\MuMu"):
        roots.append(Path(cand))
    # WSL view of the same locations, so this works from a Linux shell too.
    roots.append(Path("/mnt/c/Program Files/Netease/MuMu"))
    roots.append(Path("/mnt/c/Program Files (x86)/Netease/MuMu"))
    return roots


def _hypervisor_dirs() -> list[Path]:
    """Directories that hold the emulator's bundled VirtualBox tools."""
    out: list[Path] = []
    for root in _install_roots():
        device = root / "nx_device"
        if not device.is_dir():
            continue
        for version_dir in sorted(device.iterdir(), reverse=True):
            hyp = version_dir / "hypervisor"
            if hyp.is_dir():
                out.append(hyp)
    return out


def _search_dirs() -> list[Path]:
    dirs: list[Path] = []
    env = os.environ.get("MUMU_PATCH_TOOL_DIR")
    if env:
        dirs.append(Path(env))
    dirs.extend(_hypervisor_dirs())
    return dirs


@overload
def find_tool(name: str, *, required: Literal[True] = True) -> Tool: ...


@overload
def find_tool(name: str, *, required: Literal[False]) -> Tool | None: ...


def find_tool(name: str, *, required: bool = True) -> Tool | None:
    """Locate ``name`` (with or without ``.exe``).

    With the default ``required=True`` this either returns a tool or raises, so
    callers do not have to handle a ``None`` that cannot happen.  The overloads
    say that; the implementation still returns ``Tool | None``.
    """
    stem = name[:-4] if name.lower().endswith(".exe") else name
    filenames = [f"{stem}.exe", stem]

    for directory in _search_dirs():
        for filename in filenames:
            candidate = directory / filename
            if candidate.is_file():
                return Tool(stem, candidate)

    which = shutil.which(stem)
    if which:
        return Tool(stem, Path(which))

    if required:
        tried = "\n  ".join(str(d) for d in _search_dirs())
        raise ToolError(
            f"could not find {stem}.exe; searched:\n  {tried}\n"
            f"and PATH. Point MUMU_PATCH_TOOL_DIR at a directory containing it, "
            f"or pass --tool-dir."
        )
    return None


def _run(argv: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a helper, in a throwaway working directory.

    ``vbox-img.exe`` writes a ``logs/`` directory into whatever directory it is
    started from, so running it from the caller's cwd litters their tree.  A
    temporary cwd keeps that contained; nothing here depends on relative paths,
    because the Windows tools are given absolute translated ones.
    """
    import tempfile

    with tempfile.TemporaryDirectory(prefix="mumu-tool-") as tmp:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            cwd=tmp,
        )


def tool_version(name: str) -> str:
    """Best-effort version string, for the ``doctor`` report.

    Never raises: a tool that exists but will not run is a finding to report,
    not a reason to abort the whole check.
    """
    tool = find_tool(name, required=False)
    if tool is None:
        return ""
    probes = {
        "vbox-img": [],  # prints usage and exits non-zero
    }
    argv = [str(tool.path), *probes.get(tool.name, ["--version"])]
    try:
        result = _run(argv)
    except OSError, subprocess.SubprocessError:
        return ""
    text = (result.stdout or "") + (result.stderr or "")
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


@dataclass
class ToolReport:
    name: str
    path: Path | None
    version: str
    required: bool

    @property
    def ok(self) -> bool:
        return self.path is not None


def inspect_tools() -> list[ToolReport]:
    """Report on every helper, for ``niulai-patch doctor``.

    Only ``vbox-img`` is listed.  It is the sole externally-supplied binary the
    disk path calls, and it ships with MuMu, so a checkout normally has it.
    """
    wanted = [
        ("vbox-img", True),
    ]
    out: list[ToolReport] = []
    for name, required in wanted:
        try:
            tool = find_tool(name, required=required)
        except ToolError:
            out.append(ToolReport(name, None, "", required))
            continue
        if tool is None:
            # Optional tool, absent: report it rather than failing.
            out.append(ToolReport(name, None, "", required))
            continue
        out.append(ToolReport(name, tool.path, tool_version(name), required))
    return out


def to_windows_path(path: Path) -> str:
    """Express ``path`` the way the bundled Windows tools expect it.

    ``vbox-img.exe`` is a native Windows executable and does **not** understand
    WSL's ``/mnt/c`` mount: handed ``/mnt/c/...`` it fails with a usage error
    that looks like a bad argument, which is a confusing way to discover a path
    translation bug.  Callers must pass either a Windows path or a relative one,
    never a WSL-style absolute path.
    """
    text = str(path)
    if text.startswith("/mnt/") and len(text) > 6 and text[6] == "/":
        drive = text[5].upper()
        return f"{drive}:\\" + text[7:].replace("/", "\\")
    if len(text) > 2 and text[1] == ":":
        return text.replace("/", "\\")
    return text


def vbox_img_info(image: Path, *, timeout: int = 300) -> dict[str, str]:
    """Ask ``vbox-img.exe`` for an image's header, as a field mapping.

    This is the authority our own :mod:`disk.vdi` parser is checked
    against; the two must agree, because a disagreement means one of them is
    reading the header at the wrong offset.
    """
    tool = find_tool("vbox-img")
    result = _run(
        [str(tool.path), "info", "--filename", to_windows_path(image)],
        timeout=timeout,
    )
    text = (result.stdout or "") + (result.stderr or "")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("Header:"):
            continue
        body = line[len("Header:") :].strip()
        for part in body.split():
            if "=" in part:
                key, _, value = part.partition("=")
                fields[key] = value
    if not fields:
        raise ToolError(
            f"vbox-img.exe produced no header fields for {image}:\n{text.strip()[:500]}"
        )
    return fields
