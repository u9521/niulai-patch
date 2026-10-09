"""Locating the MuMu installation and reading its identity.

The install layout (verified against MuMu 6.8.2.0 / nx 15.0):

    <install>/
      configs/install_config.json     product name + version
      nx_main/MuMuNxMain.exe          the Qt GUI from the screenshot
      nx_main/MuMuManager.exe         CLI, byte-identical to mumu-cli.exe
      nx_device/15.0/shell/           QtWebEngine shell + CEF runtime
      nx_device/15.0/vms/             VM images
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# Default Windows locations, plus env override for tests and portable installs.
CANDIDATES = (
    r"C:\Program Files\Netease\MuMu",
    r"C:\Program Files (x86)\Netease\MuMu",
)


class InstallError(Exception):
    """Raised when no usable MuMu installation can be found."""


@dataclass
class Install:
    root: Path
    product: str
    version: str
    product_version: str
    channel: str

    @property
    def main_exe(self) -> Path:
        return self.root / "nx_main" / "MuMuNxMain.exe"

    def resolve(self, relative: str) -> Path:
        """Resolve a profile-relative target path inside the install."""
        rel = relative.replace("\\", "/").lstrip("/")
        if ".." in Path(rel).parts:
            raise InstallError(f"refusing path escape: {relative!r}")
        return self.root / rel

    def summary(self) -> str:
        return f"{self.product} {self.version} (channel {self.channel}) at {self.root}"


def _read_install_config(root: Path) -> dict:
    for rel in ("configs/install_config.json", "configs/main/install_config.json"):
        p = root / rel
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8-sig"))
            except OSError, ValueError:
                continue
    return {}


def find_install(explicit: str | Path | None = None) -> Install:
    """Locate the installation, preferring an explicit path."""
    roots: list[Path] = []
    if explicit:
        roots.append(Path(explicit))
    env = os.environ.get("MUMU_INSTALL_DIR")
    if env:
        roots.append(Path(env))
    roots.extend(Path(c) for c in CANDIDATES)

    tried: list[str] = []
    for r in roots:
        tried.append(str(r))
        if not r.is_dir():
            continue
        # Accept if either the main exe or the config is present; some partial
        # installs lack one or the other.
        if not ((r / "nx_main" / "MuMuNxMain.exe").is_file() or (r / "configs").is_dir()):
            continue
        cfg = _read_install_config(r)
        prod = cfg.get("product", {})
        return Install(
            root=r,
            product=prod.get("name", "MuMuPlayer"),
            version=prod.get("version", "unknown"),
            product_version=prod.get("product_version", prod.get("version", "unknown")),
            channel=prod.get("channel", "unknown"),
        )
    raise InstallError(
        "no MuMu installation found; tried:\n  "
        + "\n  ".join(tried)
        + "\nSet MUMU_INSTALL_DIR to override."
    )
